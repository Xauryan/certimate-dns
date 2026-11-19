// Package namesilo uses NameSilo's version 1 domain API.
package namesilo

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/dnsdrivers/registrarutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type provider struct {
	api registrarutil.API
	key string
}

func New(a *domain.Access) (dns.Provider, error) {
	key := dnsutil.Field(a, "apiKey")
	if key == "" {
		return nil, domain.ErrInvalidParams
	}
	return &provider{api: registrarutil.API{Base: "https://www.namesilo.com/api/", Client: dnsutil.HTTPClientFor(a)}, key: key}, nil
}

type record struct {
	ID       string `xml:"record_id"`
	Type     string `xml:"type"`
	Host     string `xml:"host"`
	Value    string `xml:"value"`
	TTL      int    `xml:"ttl"`
	Distance string `xml:"distance"`
}
type reply struct {
	Code    int      `xml:"code"`
	ID      string   `xml:"record_id"`
	Domains []string `xml:"domains>domain"`
	Total   *int     `xml:"pager>total"`
	Records []record `xml:"resource_record"`
}

func (p *provider) call(ctx context.Context, action string, q url.Values) (*reply, error) {
	q.Set("type", "xml")
	q.Set("version", "1")
	q.Set("key", p.key)
	// The vendor requires GET for all operations, including writes. Never expose the URL.
	body, err := p.api.Do(ctx, "GET", action+"?"+q.Encode(), "", nil)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		XMLName xml.Name `xml:"namesilo"`
		Reply   reply    `xml:"reply"`
	}
	if xml.Unmarshal(body, &envelope) != nil || envelope.Reply.Code == 0 {
		return nil, errors.New("invalid NameSilo response")
	}
	if envelope.Reply.Code != 300 {
		return nil, fmt.Errorf("NameSilo operation rejected (code %d)", envelope.Reply.Code)
	}
	return &envelope.Reply, nil
}
func (p *provider) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	r, err := p.call(ctx, "listDomains", url.Values{"page": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(dns.DNSPageSize)}})
	if err != nil {
		return nil, err
	}
	if r.Total == nil || !registrarutil.CompletePage(*r.Total, (page-1)*dns.DNSPageSize, dns.DNSPageSize, len(r.Domains)) {
		return nil, registrarutil.ErrInventory
	}
	out := dnsutil.Page[dns.Zone](page, *r.Total)
	for _, z := range r.Domains {
		name, err := dnsutil.ZoneName(z)
		if err != nil {
			return nil, registrarutil.ErrInventory
		}
		out.Items = append(out.Items, dns.Zone{ID: name, Name: name, Status: "active"})
	}
	return out, nil
}

func (p *provider) records(ctx context.Context, z string) ([]record, error) {
	r, err := p.call(ctx, "dnsListRecords", url.Values{"domain": {z}})
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, row := range r.Records {
		if _, err := dnsutil.RelativeName(row.Host, z); err != nil || seen[row.ID] || row.ID == "" || row.TTL <= 0 || row.Type == "" {
			return nil, errors.New("invalid NameSilo record response")
		}
		seen[row.ID] = true
	}
	return r.Records, nil
}
func (p *provider) DNSRecords(ctx context.Context, zone string, page int, filter string) (*dns.DNSPage[dns.DNSRecord], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return nil, err
	}
	rows, err := p.records(ctx, z)
	if err != nil {
		return nil, err
	}
	items := make([]dns.DNSRecord, 0, len(rows))
	for _, row := range rows {
		if !strings.Contains(strings.ToLower(row.Host), strings.ToLower(filter)) {
			continue
		}
		rec, err := row.view()
		if err != nil {
			return nil, err
		}
		items = append(items, rec)
	}
	return dnsutil.SlicePage(items, page)
}
func recordParams(z, name, typ, value string, ttl int) (url.Values, error) {
	host, err := dnsutil.RelativeName(name, z)
	if err != nil {
		return nil, err
	}
	if host == "@" {
		host = ""
	}
	if ttl < 3600 || ttl > 2592000 || value == "" {
		return nil, dns.ErrInvalidDNSRequest
	}
	params := url.Values{"domain": {z}, "rrhost": {host}, "rrttl": {strconv.Itoa(ttl)}}
	switch typ {
	case "A", "AAAA", "CNAME", "TXT":
	case "MX":
		priority, exchange, err := registrarutil.ParseMX(value)
		if err != nil {
			return nil, err
		}
		params.Set("rrdistance", strconv.Itoa(priority))
		value = exchange
	case "SRV":
		priority, weight, port, target, err := registrarutil.ParseSRV(value)
		if err != nil {
			return nil, err
		}
		params.Set("rrdistance", strconv.Itoa(priority))
		value = fmt.Sprintf("%d:%d:%s", weight, port, target)
	case "CAA":
		flag, tag, body, err := registrarutil.ParseCAA(value)
		if err != nil {
			return nil, err
		}
		value = fmt.Sprintf("%d:%s:%s", flag, tag, body)
	default:
		return nil, dns.ErrInvalidDNSRequest
	}
	params.Set("rrvalue", value)
	return params, nil
}
func (p *provider) write(ctx context.Context, action string, params url.Values) (string, error) {
	r, err := p.call(ctx, action, params)
	if err != nil {
		return "", err
	}
	if r.ID == "" {
		return "", errors.New("NameSilo returned no record ID")
	}
	return r.ID, nil
}
func (p *provider) CreateDNSRecord(ctx context.Context, zone string, in dns.RecordInput) (string, error) {
	if in.Priority != nil && in.Type != "MX" || in.Description != "" || in.Weight != nil {
		return "", dns.ErrInvalidDNSRequest
	}
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", err
	}
	if in.Line != "" && in.Line != "default" {
		return "", dns.ErrInvalidDNSRequest
	}
	if in.Type == "MX" {
		in.Content, err = dnsutil.MXValue(in.Type, in.Content, in.Priority, "")
		if err != nil {
			return "", err
		}
	}
	params, err := recordParams(z, in.Name, in.Type, in.Content, in.TTL)
	if err != nil {
		return "", err
	}
	params.Set("rrtype", in.Type)
	return p.write(ctx, "dnsAddRecord", params)
}
func (p *provider) record(ctx context.Context, z, id string) (*record, error) {
	rows, err := p.records(ctx, z)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.ID == id {
			return &row, nil
		}
	}
	return nil, domain.ErrRecordNotFound
}
func (p *provider) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", err
	}
	row, err := p.record(ctx, z, id)
	if err != nil {
		return "", err
	}
	in.Content, err = dnsutil.MXValue(row.Type, in.Content, nil, row.Distance+" "+row.Value)
	if err != nil {
		return "", err
	}
	params, err := recordParams(z, row.Host, row.Type, in.Content, in.TTL)
	if err != nil {
		return "", err
	}
	params.Set("rrid", id)
	return p.write(ctx, "dnsUpdateRecord", params)
}
func (p *provider) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", err
	}
	if _, err := p.record(ctx, z, id); err != nil {
		return "", err
	}
	if _, err := p.call(ctx, "dnsDeleteRecord", url.Values{"domain": {z}, "rrid": {id}}); err != nil {
		return "", err
	}
	return id, nil
}

func (row record) view() (dns.DNSRecord, error) {
	content := row.Value
	switch row.Type {
	case "MX":
		content = strings.TrimSpace(row.Distance + " " + row.Value)
	case "SRV":
		if fields := strings.SplitN(content, ":", 3); len(fields) == 3 {
			content = strings.Join([]string{row.Distance, fields[0], fields[1], fields[2]}, " ")
		}
	case "CAA":
		if fields := strings.SplitN(content, ":", 3); len(fields) == 3 {
			flag, err := strconv.ParseUint(fields[0], 10, 8)
			if err != nil {
				return dns.DNSRecord{}, registrarutil.ErrInventory
			}
			content = registrarutil.FormatCAA(int(flag), fields[1], fields[2])
		}
	}
	return dns.DNSRecord{ID: row.ID, Type: row.Type, Priority: dnsutil.MXPriority(row.Type, content), Name: row.Host, Content: content, TTL: row.TTL, Line: "default", Status: "active"}, nil
}
