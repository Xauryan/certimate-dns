// Package dnsla manages zones and individual records through DNS.LA's JSON API.
package dnsla

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/dnsdrivers/registrarutil"
	u "github.com/certimate-go/certimate/internal/dnsdrivers/selfhostutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type provider struct {
	client *u.Client
	auth   http.Header
}

func New(a *domain.Access) (dns.Provider, error) {
	id, secret := u.Field(a, "apiId"), u.Field(a, "apiSecret")
	if id == "" || secret == "" {
		return nil, domain.ErrInvalidParams
	}
	client, err := u.NewClientWithHTTP("https://api.dns.la", dnsutil.HTTPClientFor(a))
	if err != nil {
		return nil, err
	}
	return &provider{client, http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))}}}, nil
}
func (p *provider) call(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var reply struct {
		Code int
		Data json.RawMessage
	}
	if err := p.client.Call(ctx, method, path, query, body, p.auth, &reply); err != nil {
		return err
	}
	if reply.Code != 200 {
		return u.ErrProvider
	}
	if out != nil && (string(reply.Data) == "null" || json.Unmarshal(reply.Data, out) != nil) {
		return u.ErrProvider
	}
	return nil
}

type zone struct {
	ID                    u.Text
	Domain, DisplayDomain string
}

func (z zone) name() string {
	if z.Domain != "" {
		return u.Name(z.Domain)
	}
	return u.Name(z.DisplayDomain)
}

type result[T any] struct {
	Total   *int
	Results []T
}

func paging(page int) url.Values {
	return url.Values{"pageIndex": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(dns.DNSPageSize)}}
}
func (p *provider) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	if !u.PageOK(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	var data result[zone]
	if err := p.call(ctx, "GET", "/api/domainList", paging(page), nil, &data); err != nil {
		return nil, err
	}
	if data.Total == nil || data.Results == nil || !registrarutil.CompletePage(*data.Total, (page-1)*dns.DNSPageSize, dns.DNSPageSize, len(data.Results)) {
		return nil, u.ErrProvider
	}
	out := &dns.DNSPage[dns.Zone]{Items: []dns.Zone{}, Info: dns.PageInfo{Page: page, Total: *data.Total}}
	for _, z := range data.Results {
		name, err := dnsutil.ZoneName(z.name())
		if err != nil || z.ID == "" {
			return nil, u.ErrProvider
		}
		out.Items = append(out.Items, dns.Zone{ID: string(z.ID), Name: name, Status: "active"})
	}
	return out, nil
}
func (p *provider) zone(ctx context.Context, id string) (zone, error) {
	if id == "" {
		return zone{}, dns.ErrInvalidDNSRequest
	}
	var z zone
	if err := p.call(ctx, "GET", "/api/domain", url.Values{"id": {id}}, nil, &z); err != nil {
		return z, err
	}
	if _, err := dnsutil.ZoneName(z.name()); err != nil || string(z.ID) != id {
		return z, domain.ErrRecordNotFound
	}
	return z, nil
}

type record struct {
	ID         u.Text `json:"id,omitempty"`
	DomainID   u.Text `json:"domainId,omitempty"`
	Host       string `json:"host"`
	Type       int    `json:"type"`
	TTL        int    `json:"ttl"`
	Data       string `json:"data"`
	Line       u.Text `json:"lineId"`
	Preference *int   `json:"preference,omitempty"`
	Weight     *int   `json:"weight,omitempty"`
	Dominant   *bool  `json:"dominant,omitempty"`
	Disabled   bool   `json:"disable,omitempty"`
	Remark     string `json:"remark,omitempty"`
}

var typeNames = map[int]string{1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 257: "CAA"}

func (r record) kind() string {
	if r.Type == 256 {
		if r.Dominant != nil && *r.Dominant {
			return "REDIRECT_URL"
		}
		return "FORWARD_URL"
	}
	if label, ok := typeNames[r.Type]; ok {
		return label
	}
	return fmt.Sprintf("TYPE%d", r.Type)
}
func (p *provider) records(ctx context.Context, z zone, page int, filter string) (result[record], error) {
	var data result[record]
	q := paging(page)
	q.Set("domainId", string(z.ID))
	if filter != "" {
		if host, err := u.Relative(filter, z.name()); err == nil {
			filter = host
		}
		q.Set("host", filter)
	}
	err := p.call(ctx, "GET", "/api/recordList", q, nil, &data)
	if err != nil {
		return data, err
	}
	if data.Total == nil || data.Results == nil || !registrarutil.CompletePage(*data.Total, (page-1)*dns.DNSPageSize, dns.DNSPageSize, len(data.Results)) {
		return data, u.ErrProvider
	}
	for _, row := range data.Results {
		if row.ID == "" || row.Host == "" || row.Type <= 0 || row.TTL <= 0 || (row.DomainID != "" && row.DomainID != z.ID) {
			return data, u.ErrProvider
		}
	}
	return data, nil
}
func (p *provider) DNSRecords(ctx context.Context, id string, page int, filter string) (*dns.DNSPage[dns.DNSRecord], error) {
	if !u.PageOK(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	z, err := p.zone(ctx, id)
	if err != nil {
		return nil, err
	}
	data, err := p.records(ctx, z, page, filter)
	if err != nil {
		return nil, err
	}
	out := &dns.DNSPage[dns.DNSRecord]{Items: []dns.DNSRecord{}, Info: dns.PageInfo{Page: page, Total: *data.Total}}
	for _, r := range data.Results {
		out.Items = append(out.Items, dns.DNSRecord{ID: string(r.ID), Priority: r.Preference, Weight: r.Weight, Description: r.Remark, Name: u.Full(r.Host, z.name()), Type: r.kind(), Content: r.content(), TTL: r.TTL, Line: string(r.Line), Status: u.Status(r.Disabled)})
	}
	return out, nil
}
func (p *provider) CreateDNSRecord(ctx context.Context, id string, in dns.RecordInput) (string, error) {
	if in.Priority != nil && in.Type != "MX" || in.Description != "" {
		return "", dns.ErrInvalidDNSRequest
	}
	z, err := p.zone(ctx, id)
	if err != nil {
		return "", err
	}
	host, err := u.Relative(in.Name, z.name())
	if err != nil {
		return "", err
	}
	body := record{DomainID: z.ID, Host: host, Line: wireLine(in.Line), TTL: in.TTL, Weight: in.Weight}
	if in.Weight != nil && *in.Weight < 0 {
		return "", dns.ErrInvalidDNSRequest
	}
	if in.Type == "MX" {
		in.Content, err = dnsutil.MXValue(in.Type, in.Content, in.Priority, "")
		if err != nil {
			return "", err
		}
	}
	switch in.Type {
	case "REDIRECT_URL", "FORWARD_URL":
		redirect := in.Type == "REDIRECT_URL"
		body.Type, body.Dominant = 256, &redirect
	default:
		for number, label := range typeNames {
			if label == in.Type {
				body.Type = number
				break
			}
		}
	}
	if body.Type == 0 {
		return "", dns.ErrInvalidDNSRequest
	}
	if err := body.setContent(in.Content); err != nil {
		return "", err
	}
	var reply struct{ ID u.Text }
	if err = p.call(ctx, "POST", "/api/record", nil, body, &reply); err != nil {
		return "", err
	}
	if reply.ID == "" {
		return "", u.ErrProvider
	}
	return string(reply.ID), nil
}

// PUT and DELETE use account-wide IDs. Only a record from the selected zone may be changed.
func (p *provider) find(ctx context.Context, zoneID, id string) (record, error) {
	z, err := p.zone(ctx, zoneID)
	if err != nil {
		return record{}, err
	}
	if id == "" {
		return record{}, dns.ErrInvalidDNSRequest
	}
	var found record
	err = registrarutil.Walk(dns.DNSPageSize, func(page int) ([]record, int, error) {
		rows, err := p.records(ctx, z, page, "")
		if err != nil {
			return nil, 0, err
		}
		return rows.Results, *rows.Total, nil
	}, func(r record) string { return string(r.ID) }, func(r record) error {
		if string(r.ID) == id {
			found = r
		}
		return nil
	})
	if err != nil {
		return record{}, err
	}
	if found.ID == "" {
		return record{}, domain.ErrRecordNotFound
	}
	return found, nil
}
func (p *provider) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	r, err := p.find(ctx, zone, id)
	if err != nil {
		return "", err
	}
	r.DomainID = ""
	r.TTL = in.TTL
	in.Content, err = dnsutil.MXValue(r.kind(), in.Content, nil, r.content())
	if err != nil {
		return "", err
	}
	if err := r.setContent(in.Content); err != nil {
		return "", err
	}
	if err = p.call(ctx, "PUT", "/api/record", nil, r, nil); err != nil {
		return "", err
	}
	return id, nil
}
func (p *provider) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	if _, err := p.find(ctx, zone, id); err != nil {
		return "", err
	}
	if err := p.call(ctx, "DELETE", "/api/record", url.Values{"id": {id}}, nil, nil); err != nil {
		return "", err
	}
	return id, nil
}

func wireLine(v string) u.Text {
	if v == "default" || v == "0" {
		return ""
	}
	return u.Text(v)
}

func (r record) content() string {
	if r.Type == 15 && r.Preference != nil {
		return fmt.Sprintf("%d %s", *r.Preference, r.Data)
	}
	return r.Data
}

func (r *record) setContent(content string) error {
	if content == "" || r.TTL <= 0 {
		return dns.ErrInvalidDNSRequest
	}
	if r.Type == 15 {
		priority, exchange, err := registrarutil.ParseMX(content)
		if err != nil {
			return err
		}
		r.Preference, r.Data = &priority, exchange
	} else {
		r.Data = content
	}
	return nil
}

func (p *provider) CreateZone(ctx context.Context, name string) (*dns.Zone, error) {
	z, err := dnsutil.ZoneName(name)
	if err != nil {
		return nil, err
	}
	var result struct{ ID u.Text }
	if err := p.call(ctx, "POST", "/api/domain", nil, map[string]string{"domain": z}, &result); err != nil {
		return nil, err
	}
	if result.ID == "" {
		return nil, u.ErrProvider
	}
	return &dns.Zone{ID: string(result.ID), Name: z, Status: "active"}, nil
}

func (p *provider) ZoneDetails(ctx context.Context, id string) (*dns.ZoneDetails, error) {
	z, err := p.zone(ctx, id)
	if err != nil {
		return nil, err
	}
	var measures struct{ MinTTL *int }
	if err := p.call(ctx, "GET", "/api/dnsMeasures", url.Values{"id": {id}}, nil, &measures); err != nil {
		return nil, err
	}
	var lines []struct {
		ID, PID u.Text
		Value   string
		Order   int
	}
	if err := p.call(ctx, "GET", "/api/availableLine", url.Values{"domain": {z.name()}}, nil, &lines); err != nil {
		return nil, err
	}
	if lines == nil || measures.MinTTL == nil {
		return nil, u.ErrProvider
	}
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].Order < lines[j].Order })
	out := &dns.ZoneDetails{Name: z.name(), MinTTL: *measures.MinTTL, Lines: []dns.RecordLine{}}
	for _, l := range lines {
		out.Lines = append(out.Lines, dns.RecordLine{ID: string(wireLine(string(l.ID))), Name: l.Value, Parent: string(wireLine(string(l.PID)))})
	}
	return out, nil
}

func (p *provider) BatchFields() []string { return []string{"status", "line", "weight"} }

func (p *provider) BatchAttribute(ctx context.Context, zone, id, field string) (string, error) {
	r, err := p.find(ctx, zone, id)
	if err != nil {
		return "", err
	}
	switch field {
	case "status":
		if r.Disabled {
			return "disabled", nil
		}
		return "enabled", nil
	case "line":
		return string(r.Line), nil
	case "weight":
		if r.Weight == nil {
			return "", nil
		}
		return strconv.Itoa(*r.Weight), nil
	}
	return "", dns.ErrInvalidDNSRequest
}

func (p *provider) SetBatchAttribute(ctx context.Context, zone, id, field, value string) error {
	r, err := p.find(ctx, zone, id)
	if err != nil {
		return err
	}
	switch field {
	case "status":
		if value != "enabled" && value != "disabled" {
			return dns.ErrInvalidDNSRequest
		}
		return p.call(ctx, "PUT", "/api/recordDisable", nil, map[string]any{"id": id, "disable": value == "disabled"}, nil)
	case "line":
		r.Line = wireLine(strings.TrimSpace(value))
	case "weight":
		v, err := strconv.Atoi(value)
		if err != nil || v < 0 {
			return dns.ErrInvalidDNSRequest
		}
		r.Weight = &v
	default:
		return dns.ErrInvalidDNSRequest
	}
	r.DomainID = ""
	return p.call(ctx, "PUT", "/api/record", nil, r, nil)
}
