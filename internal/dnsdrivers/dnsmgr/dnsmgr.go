// Package dnsmgr manages DNS through the Rainbow DNS Manager signed form API.
package dnsmgr

import (
	"bytes"
	"context"
	"crypto/md5" // Upstream DNSMgr uses MD5 for legacy accounts.
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	u "github.com/certimate-go/certimate/internal/dnsdrivers/selfhostutil"
	"github.com/certimate-go/certimate/internal/dnssign"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type provider struct {
	client        *u.Client
	uid, key      string
	signatureMode string
}

func New(a *domain.Access) (dns.Provider, error) {
	uid, key := u.Field(a, "uid"), u.Field(a, "apiKey")
	if uid == "" || key == "" {
		return nil, domain.ErrInvalidParams
	}
	mode, ok := a.Config["signatureMode"].(string)
	if _, exists := a.Config["signatureMode"]; exists && !ok {
		return nil, domain.ErrInvalidParams
	}
	switch mode {
	case "", "legacy":
		mode = "legacy"
	case "v2":
	default:
		return nil, domain.ErrInvalidParams
	}
	c, err := u.NewClientWithHTTP(u.Field(a, "serverUrl"), dnsutil.HTTPClientFor(a))
	if err != nil {
		return nil, err
	}
	return &provider{client: c, uid: uid, key: key, signatureMode: mode}, nil
}
func (p *provider) post(ctx context.Context, path string, v url.Values, out any) error {
	if v == nil {
		v = url.Values{}
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	v.Set("uid", p.uid)
	v.Set("timestamp", ts)
	requestPath := "/api/" + path
	if p.signatureMode == "v2" {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return u.ErrProvider
		}
		v.Set("sign_version", "2")
		v.Set("nonce", hex.EncodeToString(nonce[:]))
		// DNSMgr routes are rooted at /api even behind a proxy that strips a URL prefix.
		v.Set("sign", dnssign.Sign(requestPath, v, p.key))
	} else {
		sum := md5.Sum([]byte(p.uid + ts + p.key))
		v.Set("sign", hex.EncodeToString(sum[:]))
	}
	var raw json.RawMessage
	if err := p.client.Call(ctx, "POST", requestPath, nil, v, nil, &raw); err != nil {
		return err
	}
	if len(raw) == 0 {
		return u.ErrProvider
	}
	if raw[0] == '{' {
		var envelope struct {
			Code *int
			ID   u.Text
			Data json.RawMessage
		}
		if json.Unmarshal(raw, &envelope) != nil {
			return u.ErrProvider
		}
		if envelope.Code != nil {
			if *envelope.Code != 0 {
				return u.ErrProvider
			}
			if out == nil {
				return nil
			}
			if id, ok := out.(*mutationID); ok {
				*id = mutationID(envelope.ID)
				return nil
			}
			raw = envelope.Data
		} else if out == nil {
			return u.ErrProvider
		}
	} else if out == nil {
		return u.ErrProvider
	}
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, out) != nil {
		return u.ErrProvider
	}
	return nil
}

type pageData[T any] struct {
	Total *int
	Rows  []T
}

func paging(n int) url.Values {
	return url.Values{"offset": {strconv.Itoa((n - 1) * dns.DNSPageSize)}, "limit": {strconv.Itoa(dns.DNSPageSize)}}
}

type zone struct {
	Config struct {
		Type          string
		RecordEdit    *dns.RecordEditCapabilities
		NativeRecords bool
	}
	ID         u.Text
	Name       string
	MinTTL     int
	RecordLine []struct {
		ID, Parent u.Text
		Name       string
	}
}

func (p *provider) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	if !u.PageOK(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	var data pageData[zone]
	if err := p.post(ctx, "domain", paging(page), &data); err != nil {
		return nil, err
	}
	if data.Rows == nil || data.Total == nil || !u.CompletePage(page, *data.Total, len(data.Rows)) {
		return nil, u.ErrProvider
	}
	out := &dns.DNSPage[dns.Zone]{Items: []dns.Zone{}, Info: dns.PageInfo{Page: page, Total: *data.Total}}
	for _, r := range data.Rows {
		if _, err := dnsutil.PositiveID(string(r.ID)); err != nil {
			return nil, u.ErrProvider
		}
		if _, err := dnsutil.ZoneName(r.Name); err != nil {
			return nil, u.ErrProvider
		}
		out.Items = append(out.Items, dns.Zone{ID: string(r.ID), Name: u.Name(r.Name), Status: "active"})
	}
	return out, nil
}
func (p *provider) zone(ctx context.Context, id string) (zone, error) {
	n, err := strconv.ParseUint(id, 10, 63)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != id {
		return zone{}, dns.ErrInvalidDNSRequest
	}
	var z zone
	err = p.post(ctx, "domain/"+id, url.Values{"loginurl": {"0"}}, &z)
	if err != nil {
		return z, err
	}
	if _, err := dnsutil.ZoneName(z.Name); string(z.ID) != id || err != nil {
		return z, domain.ErrRecordNotFound
	}
	return z, nil
}

type record struct {
	RecordID, Line, TTL, Status, Weight, MX       u.Text
	Domain, Name, Type, Value, Remark, UpdateTime string
	Proxied                                       bool
	Native                                        *dns.DNSRecord
}

func (r record) dns(z zone) (dns.DNSRecord, error) {
	ttl, err := strconv.Atoi(string(r.TTL))
	if err != nil || r.RecordID == "" || (r.Domain != "" && u.Name(r.Domain) != u.Name(z.Name)) {
		return dns.DNSRecord{}, u.ErrProvider
	}
	if r.Name == "" || r.Type == "" || ttl < 0 {
		return dns.DNSRecord{}, u.ErrProvider
	}
	if z.Config.NativeRecords {
		if r.Native == nil || r.Native.ID != string(r.RecordID) || r.Native.Type != r.Type || r.Native.TTL != ttl {
			return dns.DNSRecord{}, u.ErrProvider
		}
		if _, err := dnsutil.RelativeName(r.Native.Name, z.Name); err != nil {
			return dns.DNSRecord{}, u.ErrProvider
		}
		return *r.Native, nil
	}
	status := "enabled"
	if r.Status == "0" {
		status = "disabled"
	}
	var priority *int
	if r.Type == "MX" {
		priority = integer(r.MX)
	}
	weight := integer(r.Weight)
	if z.Config.Type == "bt" && (r.Type == "MX" || weight != nil && *weight <= 1) {
		weight = nil // Older Baota adapters return their shared MX/weight field twice.
	}
	return dns.DNSRecord{ID: string(r.RecordID), Name: u.Full(r.Name, z.Name), Type: r.Type, Content: r.Value, TTL: ttl, Line: string(r.Line), Status: status, Description: r.Remark, Weight: weight, Priority: priority, UpdatedAt: r.UpdateTime, Proxied: r.Proxied || z.Config.Type == "cloudflare" && r.Line == "1"}, nil
}
func (p *provider) records(ctx context.Context, z zone, page int, q url.Values) (pageData[record], error) {
	var raw json.RawMessage
	v := paging(page)
	for k, vs := range q {
		v[k] = vs
	}
	if z.Config.NativeRecords {
		v.Set("native_records", "1")
	}
	if err := p.post(ctx, "record/data/"+string(z.ID), v, &raw); err != nil {
		return pageData[record]{}, err
	}
	var data pageData[record]
	// Some upstream backends return the entire array for browser-side pagination.
	if len(raw) > 0 && raw[0] == '[' {
		var rows []record
		if json.Unmarshal(raw, &rows) != nil {
			return data, u.ErrProvider
		}
		pg, err := u.SlicePage(rows, page)
		if err != nil {
			return data, err
		}
		data.Rows = pg.Items
		data.Total = &pg.Info.Total
	} else if json.Unmarshal(raw, &data) != nil || data.Rows == nil {
		return data, u.ErrProvider
	}
	if data.Total == nil || !u.CompletePage(page, *data.Total, len(data.Rows)) {
		return data, u.ErrProvider
	}
	for _, r := range data.Rows {
		if _, err := r.dns(z); err != nil {
			return data, err
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
	q := url.Values{}
	if filter != "" {
		if host, err := u.Relative(filter, z.Name); err == nil {
			filter = host
		}
		q.Set("keyword", filter)
	}
	data, err := p.records(ctx, z, page, q)
	if err != nil {
		return nil, err
	}
	out := &dns.DNSPage[dns.DNSRecord]{Items: []dns.DNSRecord{}, Info: dns.PageInfo{Page: page, Total: *data.Total}}
	for _, r := range data.Rows {
		row, _ := r.dns(z)
		out.Items = append(out.Items, row)
	}
	return out, nil
}
func integer(v u.Text) *int {
	n, err := strconv.Atoi(string(v))
	if err != nil {
		return nil
	}
	return &n
}
func (p *provider) walk(ctx context.Context, z zone, q url.Values, visit func(record) error) error {
	seen := map[u.Text]bool{}
	total := -1
	for page := 1; u.PageOK(page); page++ {
		data, err := p.records(ctx, z, page, q)
		if err != nil {
			return err
		}
		if total != -1 && total != *data.Total {
			return u.ErrProvider
		}
		total = *data.Total
		for _, r := range data.Rows {
			if seen[r.RecordID] {
				return u.ErrProvider
			}
			seen[r.RecordID] = true
			if err := visit(r); err != nil {
				return err
			}
		}
		if len(seen) == total {
			return nil
		}
	}
	return u.ErrProvider
}
func (p *provider) CreateDNSRecord(ctx context.Context, id string, in dns.RecordInput) (string, error) {
	z, err := p.zone(ctx, id)
	if err != nil {
		return "", err
	}
	host, err := u.Relative(in.Name, z.Name)
	if err != nil {
		return "", err
	}
	defer u.LockZone(p.client.Base, id)()
	line := in.Line
	if line == "" {
		line = "default"
	}
	q := url.Values{"subdomain": {host}, "type": {in.Type}, "value": {in.Content}}
	same := func(r record) bool {
		return strings.EqualFold(r.Name, host) && r.Type == in.Type && r.Value == in.Content && (string(r.Line) == line || r.Line == "" && line == "default")
	}
	prior := map[u.Text]bool{}
	if err = p.walk(ctx, z, q, func(r record) error {
		prior[r.RecordID] = true
		if same(r) {
			return dns.ErrInvalidDNSRequest
		}
		return nil
	}); err != nil {
		return "", err
	}
	v := url.Values{"name": {host}, "type": {in.Type}, "value": {in.Content}, "line": {line}, "ttl": {strconv.Itoa(in.TTL)}}
	if in.Description != "" {
		v.Set("remark", in.Description)
	}
	if in.Weight != nil {
		v.Set("weight", strconv.Itoa(*in.Weight))
	}
	if in.Type == "MX" && in.Priority != nil {
		v.Set("mx", strconv.Itoa(*in.Priority))
	}
	if err = p.post(ctx, "record/add/"+id, v, nil); err != nil {
		return "", err
	}
	// The create response has no record ID. Resolve the created value within its zone.
	var created u.Text
	err = p.walk(ctx, z, q, func(r record) error {
		if !prior[r.RecordID] && same(r) {
			if created != "" {
				return u.ErrProvider
			}
			created = r.RecordID
		}
		return nil
	})
	if err != nil || created == "" {
		return "", u.ErrProvider
	}
	return string(created), nil
}
func (p *provider) old(ctx context.Context, zoneID, id string) (record, error) {
	if id == "" {
		return record{}, dns.ErrInvalidDNSRequest
	}
	z, err := p.zone(ctx, zoneID)
	if err != nil {
		return record{}, err
	}
	return p.oldInZone(ctx, z, id)
}
func (p *provider) oldInZone(ctx context.Context, z zone, id string) (record, error) {
	var found record
	err := p.walk(ctx, z, nil, func(r record) error {
		if string(r.RecordID) == id {
			found = r
		}
		return nil
	})
	if err != nil {
		return record{}, err
	}
	if found.RecordID == "" {
		return record{}, domain.ErrRecordNotFound
	}
	return found, nil
}
func (p *provider) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	defer u.LockZone(p.client.Base, zone)()
	r, err := p.old(ctx, zone, id)
	if err != nil {
		return "", err
	}
	r.TTL = u.Text(strconv.Itoa(in.TTL))
	r.Value = in.Content
	if err = p.update(ctx, zone, r); err != nil {
		return "", err
	}
	return id, nil
}
func (p *provider) update(ctx context.Context, zone string, r record) error {
	return p.post(ctx, "record/update/"+zone, r.updateForm(), nil)
}
func (r record) updateForm() url.Values {
	v := url.Values{"recordid": {string(r.RecordID)}, "name": {r.Name}, "type": {r.Type}, "line": {string(r.Line)}, "value": {r.Value}, "ttl": {string(r.TTL)}, "remark": {r.Remark}}
	if r.MX != "" {
		v.Set("mx", string(r.MX))
	}
	if r.Weight != "" {
		v.Set("weight", string(r.Weight))
	}
	return v
}
func (p *provider) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	defer u.LockZone(p.client.Base, zone)()
	if _, err := p.old(ctx, zone, id); err != nil {
		return "", err
	}
	if err := p.post(ctx, "record/delete/"+zone, url.Values{"recordid": {id}}, nil); err != nil {
		return "", err
	}
	return id, nil
}

func (p *provider) ZoneDetails(ctx context.Context, id string) (*dns.ZoneDetails, error) {
	z, err := p.zone(ctx, id)
	if err != nil {
		return nil, err
	}
	caps := z.editCapabilities()
	out := &dns.ZoneDetails{Name: z.Name, Status: "active", MinTTL: z.MinTTL, Lines: []dns.RecordLine{}, RecordEdit: &caps}
	for _, line := range z.RecordLine {
		out.Lines = append(out.Lines, dns.RecordLine{ID: string(line.ID), Name: line.Name, Parent: string(line.Parent)})
	}
	return out, nil
}
func (p *provider) BatchFields() []string { return []string{"status", "remark", "weight", "line"} }
func (p *provider) BatchAttribute(ctx context.Context, zone, id, field string) (string, error) {
	r, err := p.old(ctx, zone, id)
	if err != nil {
		return "", err
	}
	switch field {
	case "status":
		if r.Status == "0" {
			return "disabled", nil
		}
		return "enabled", nil
	case "remark":
		return r.Remark, nil
	case "line":
		return string(r.Line), nil
	case "weight":
		return string(r.Weight), nil
	}
	return "", dns.ErrInvalidDNSRequest
}
func (p *provider) SetBatchAttribute(ctx context.Context, zone, id, field, value string) error {
	defer u.LockZone(p.client.Base, zone)()
	r, err := p.old(ctx, zone, id)
	if err != nil {
		return err
	}
	v := url.Values{"recordid": {id}}
	switch field {
	case "status":
		if value != "enabled" && value != "disabled" {
			return dns.ErrInvalidDNSRequest
		}
		status := "0"
		if value == "enabled" {
			status = "1"
		}
		v.Set("status", status)
	case "remark":
		v.Set("remark", value)
	case "weight":
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			return dns.ErrInvalidDNSRequest
		}
		r.Weight = u.Text(value)
		return p.update(ctx, zone, r)
	case "line":
		if value == "" {
			return dns.ErrInvalidDNSRequest
		}
		r.Line = u.Text(value)
		return p.update(ctx, zone, r)
	default:
		return dns.ErrInvalidDNSRequest
	}
	return p.post(ctx, "record/"+field+"/"+zone, v, nil)
}
