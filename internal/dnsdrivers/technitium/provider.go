// Package technitium manages authoritative zones on a Technitium DNS Server.
package technitium

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/dnsdrivers/selfhostutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

var failure = errors.New("Technitium DNS returned an unexpected response; refresh the zone before retrying a change")

type provider struct {
	client *selfhostutil.Client
	token  string
}

func New(a *domain.Access) (dns.Provider, error) {
	c, err := selfhostutil.NewClientWithHTTP(dnsutil.Field(a, "serverUrl"), dnsutil.HTTPClientFor(a))
	if err != nil {
		return nil, err
	}
	token := dnsutil.Field(a, "apiToken")
	if token == "" {
		return nil, domain.ErrInvalidParams
	}
	if allow, _ := a.Config["allowInsecureConnections"].(bool); allow {
		selected, ok := dnsutil.TransportFor(a).(*http.Transport)
		if !ok {
			return nil, domain.ErrInvalidParams
		}
		tr := selected.Clone()
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{}
		}
		tr.TLSClientConfig.InsecureSkipVerify = true // Explicitly selected for this access.
		c.HTTP.Transport = tr
	}
	return &provider{c, token}, nil
}

func (p *provider) call(ctx context.Context, path string, data url.Values, out any) error {
	// The web service accepts form-encoded POSTs for its read and write APIs.
	// Keep the session token in the body, including on older servers.
	data.Set("token", p.token)
	var envelope struct {
		Status   string
		Response json.RawMessage
	}
	if err := p.client.Call(ctx, http.MethodPost, "/api/"+path, nil, data, nil, &envelope); err != nil {
		return err
	}
	if envelope.Status != "ok" {
		return failure
	}
	if out != nil && (len(envelope.Response) == 0 || string(envelope.Response) == "null" || json.Unmarshal(envelope.Response, out) != nil) {
		return failure
	}
	return nil
}

type zoneInfo struct {
	Name, Type         string
	Disabled, Internal bool
}

func status(disabled bool) string {
	if disabled {
		return "disabled"
	}
	return "enabled"
}
func (p *provider) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	var resp struct{ Zones []zoneInfo }
	if err := p.call(ctx, "zones/list", url.Values{}, &resp); err != nil {
		return nil, err
	}
	if resp.Zones == nil {
		return nil, failure
	}
	var zones []dns.Zone
	for _, z := range resp.Zones {
		if z.Name == "" || z.Name == "." {
			continue
		} // The application models named domains.
		name, err := dnsutil.ZoneName(z.Name)
		if err != nil {
			return nil, failure
		}
		zones = append(zones, dns.Zone{ID: name, Name: name, Status: status(z.Disabled)})
	}
	return dnsutil.SlicePage(zones, page)
}
func (p *provider) CreateZone(ctx context.Context, raw string) (*dns.Zone, error) {
	name, err := dnsutil.ZoneName(raw)
	if err != nil {
		return nil, err
	}
	var out struct{ Domain string }
	if err = p.call(ctx, "zones/create", url.Values{"zone": {name}, "type": {"Primary"}}, &out); err != nil {
		return nil, err
	}
	if !strings.EqualFold(out.Domain, name) {
		return nil, failure
	}
	return &dns.Zone{ID: name, Name: name, Status: "enabled"}, nil
}

type nativeRecord struct {
	Name, Type, Comments string
	TTL                  *int
	Disabled             bool
	ExpiryTTL            int
	GlueRecords          []string
	RData                map[string]json.RawMessage
}
type record struct {
	dns.DNSRecord
	selector url.Values
	expiry   int
	glue     string
}

var keys = map[string][]string{
	"A": {"ipAddress"}, "AAAA": {"ipAddress"}, "CNAME": {"cname"}, "NS": {"nameServer"},
	"TXT": {"text"}, "MX": {"exchange", "preference"}, "SRV": {"priority", "weight", "port", "target"},
	"PTR": {"ptrName"}, "CAA": {"flags", "tag", "value"}, "ANAME": {"aname"}, "DNAME": {"dname"},
	"APP": {"appName", "classPath", "recordData"},
}

func scalar(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && string(raw) != "null" {
		return s, true
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		if _, err := n.Int64(); err == nil {
			return n.String(), true
		}
	}
	return "", false
}
func parseRecord(zone string, n nativeRecord) (record, error) {
	host, err := dnsutil.RelativeName(n.Name, zone)
	if err != nil || n.Name == "@" || n.Type == "" || n.TTL == nil || n.RData == nil {
		return record{}, failure
	}
	r := record{DNSRecord: dns.DNSRecord{Name: dnsutil.FullName(host, zone), Type: n.Type, TTL: *n.TTL, Status: status(n.Disabled), Description: n.Comments, Line: "default"}, expiry: n.ExpiryTTL}
	fields, ok := keys[n.Type]
	if !ok {
		// Private provider configuration can occur in FWD and other opaque records.
		// Never serialize that data into the displayed value or the external identifier.
		r.ReadOnly = true
		canonical, _ := json.Marshal(n.RData)
		r.ID = selfhostutil.ID(zone, r.Name, r.Type, string(canonical))
		return r, nil
	}
	r.selector = url.Values{}
	var parts []string
	for _, key := range fields {
		raw := n.RData[key]
		if key == "recordData" && raw == nil {
			raw = n.RData["data"]
		}
		value, ok := scalar(raw)
		if !ok && !(n.Type == "APP" && key == "recordData") {
			return record{}, failure
		}
		r.selector.Set(key, value)
		parts = append(parts, value)
	}
	switch n.Type {
	case "MX":
		v, e := strconv.Atoi(parts[1])
		if e != nil {
			return record{}, failure
		}
		r.Priority = &v
		r.Content = parts[0]
	case "CAA":
		r.Content = parts[0] + " " + parts[1] + " " + strconv.Quote(parts[2])
	case "TXT":
		r.Content = parts[0]
		if raw, ok := n.RData["characterStringsBase64"]; ok {
			var chunks []string
			if json.Unmarshal(raw, &chunks) != nil || len(chunks) == 0 {
				return record{}, failure
			}
			r.selector.Del("text")
			r.selector.Set("characterStringsBase64", strings.Join(chunks, ","))
		} else if string(n.RData["splitText"]) == "true" {
			r.selector.Set("splitText", "true")
		}
	case "NS":
		r.Content = parts[0]
		r.glue = strings.Join(n.GlueRecords, ",")
	default:
		r.Content = strings.TrimSuffix(strings.Join(parts, " "), " ")
	}
	r.ID = selfhostutil.ID(zone, r.Name, r.Type, r.selector.Encode())
	return r, nil
}

func (p *provider) records(ctx context.Context, raw string) (zoneInfo, []record, error) {
	name, err := dnsutil.ZoneName(raw)
	if err != nil {
		return zoneInfo{}, nil, err
	}
	var out struct {
		Zone    zoneInfo
		Records []nativeRecord
	}
	if err := p.call(ctx, "zones/records/get", url.Values{"zone": {name}, "domain": {name}, "listZone": {"true"}}, &out); err != nil {
		return zoneInfo{}, nil, err
	}
	if !strings.EqualFold(out.Zone.Name, name) || out.Records == nil {
		return zoneInfo{}, nil, failure
	}
	rows := make([]record, 0, len(out.Records))
	ids := make(map[string]bool)
	for _, n := range out.Records {
		r, err := parseRecord(name, n)
		if err != nil || ids[r.ID] {
			return zoneInfo{}, nil, failure
		}
		if out.Zone.Internal || out.Zone.Type == "Secondary" || out.Zone.Type == "Stub" {
			r.ReadOnly = true
		}
		ids[r.ID] = true
		rows = append(rows, r)
	}
	return out.Zone, rows, nil
}
func (p *provider) DNSRecords(ctx context.Context, zone string, page int, name string) (*dns.DNSPage[dns.DNSRecord], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	z, rows, err := p.records(ctx, zone)
	if err != nil {
		return nil, err
	}
	if name != "" {
		host, err := dnsutil.RelativeName(name, z.Name)
		if err != nil {
			return nil, err
		}
		name = dnsutil.FullName(host, z.Name)
	}
	var result []dns.DNSRecord
	for _, r := range rows {
		if name == "" || strings.EqualFold(r.Name, name) {
			result = append(result, r.DNSRecord)
		}
	}
	return dnsutil.SlicePage(result, page)
}
func (p *provider) ZoneDetails(ctx context.Context, zone string) (*dns.ZoneDetails, error) {
	z, _, err := p.records(ctx, zone)
	if err != nil {
		return nil, err
	}
	return &dns.ZoneDetails{Name: z.Name, Status: status(z.Disabled), Plan: z.Type, Lines: []dns.RecordLine{{ID: "default", Name: "Default"}}}, nil
}
func (p *provider) current(ctx context.Context, zone, id string) (record, error) {
	_, rows, err := p.records(ctx, zone)
	if err != nil {
		return record{}, err
	}
	for _, r := range rows {
		if r.ID == id {
			if r.ReadOnly {
				return record{}, dns.ErrInvalidDNSRequest
			}
			return r, nil
		}
	}
	return record{}, domain.ErrRecordNotFound
}
func valueParams(typ, content string, priority *int) (url.Values, error) {
	fields := keys[typ]
	if len(fields) == 0 || content == "" {
		return nil, dns.ErrInvalidDNSRequest
	}
	values := []string{content}
	switch typ {
	case "MX":
		n := 1
		if priority != nil {
			n = *priority
		}
		if n < 0 || n > 65535 {
			return nil, dns.ErrInvalidDNSRequest
		}
		values = append(values, strconv.Itoa(n))
	case "SRV":
		values = strings.Fields(content)
	case "CAA":
		values = strings.SplitN(content, " ", 3)
		if len(values) == 3 && strings.HasPrefix(values[2], "\"") {
			v, err := strconv.Unquote(values[2])
			if err != nil {
				return nil, dns.ErrInvalidDNSRequest
			}
			values[2] = v
		}
	case "APP":
		values = strings.SplitN(content, " ", 3)
		if len(values) == 2 {
			values = append(values, "")
		}
	}
	if len(values) != len(fields) {
		return nil, dns.ErrInvalidDNSRequest
	}
	v := url.Values{}
	for i, k := range fields {
		v.Set(k, values[i])
	}
	return v, nil
}
func (p *provider) write(ctx context.Context, zone, path string, v url.Values) (string, error) {
	var out struct {
		Zone                       zoneInfo
		AddedRecord, UpdatedRecord *nativeRecord
	}
	if err := p.call(ctx, "zones/records/"+path, v, &out); err != nil {
		return "", err
	}
	n := out.UpdatedRecord
	if path == "add" {
		n = out.AddedRecord
	}
	name := v.Get("domain")
	if dest := v.Get("newDomain"); dest != "" {
		name = dest
	}
	if !strings.EqualFold(out.Zone.Name, zone) || n == nil || !strings.EqualFold(n.Name, name) || n.Type != v.Get("type") {
		return "", failure
	}
	r, err := parseRecord(zone, *n)
	return r.ID, err
}
func (p *provider) CreateDNSRecord(ctx context.Context, zone string, in dns.RecordInput) (string, error) {
	if (in.Line != "" && in.Line != "default") || in.TTL < 1 || in.Weight != nil || (in.Priority != nil && in.Type != "MX") {
		return "", dns.ErrInvalidDNSRequest
	}
	name, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", err
	}
	host, err := dnsutil.RelativeName(in.Name, name)
	if err != nil {
		return "", err
	}
	v, err := valueParams(in.Type, in.Content, in.Priority)
	if err != nil {
		return "", err
	}
	// Technitium can select the closest enclosing zone if the requested zone
	// disappeared. Confirm the exact zone before posting its record.
	info, _, err := p.records(ctx, name)
	if err != nil {
		return "", err
	}
	if info.Internal || info.Type == "Secondary" || info.Type == "Stub" {
		return "", dns.ErrInvalidDNSRequest
	}
	v.Set("zone", name)
	v.Set("domain", dnsutil.FullName(host, name))
	v.Set("type", in.Type)
	v.Set("ttl", strconv.Itoa(in.TTL))
	v.Set("overwrite", "false")
	if in.Description != "" {
		v.Set("comments", in.Description)
	}
	return p.write(ctx, name, "add", v)
}
func (p *provider) update(ctx context.Context, zone string, r record, content string, ttl int, disabled bool, comments string) (string, error) {
	return p.updateFields(ctx, zone, r, r.Name, content, r.Priority, ttl, disabled, comments)
}
func (p *provider) updateFields(ctx context.Context, zone string, r record, name, content string, priority *int, ttl int, disabled bool, comments string) (string, error) {
	v := r.selector
	if name != r.Name {
		v.Set("newDomain", name)
	}
	priorityChanged := priority != nil && (r.Priority == nil || *r.Priority != *priority)
	if content != r.Content || priorityChanged {
		next, err := valueParams(r.Type, content, priority)
		if err != nil {
			return "", err
		}
		for k, vv := range next {
			switch r.Type {
			case "CNAME", "DNAME", "APP":
				v.Set(k, vv[0]) // singletons identify the existing record by owner/type
			default:
				v.Set("new"+strings.ToUpper(k[:1])+k[1:], vv[0])
			}
		}
	}
	if r.glue != "" {
		v.Set("glue", r.glue)
	}
	v.Set("zone", zone)
	v.Set("domain", r.Name)
	v.Set("type", r.Type)
	v.Set("ttl", strconv.Itoa(ttl))
	v.Set("disable", strconv.FormatBool(disabled))
	v.Set("comments", comments)
	v.Set("expiryTtl", strconv.Itoa(r.expiry))
	return p.write(ctx, zone, "update", v)
}
func (p *provider) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	if in.TTL < 1 || in.Content == "" {
		return "", dns.ErrInvalidDNSRequest
	}
	r, err := p.current(ctx, zone, id)
	if err != nil {
		return "", err
	}
	return p.update(ctx, zone, r, in.Content, in.TTL, r.Status == "disabled", r.Description)
}
func (p *provider) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	r, err := p.current(ctx, zone, id)
	if err != nil {
		return "", err
	}
	v := r.selector
	v.Set("zone", zone)
	v.Set("domain", r.Name)
	v.Set("type", r.Type)
	if err := p.call(ctx, "zones/records/delete", v, nil); err != nil {
		return "", err
	}
	return id, nil
}
func (p *provider) SetDNSRecordStatus(ctx context.Context, zone, id string, on bool) (string, error) {
	r, err := p.current(ctx, zone, id)
	if err != nil {
		return "", err
	}
	return p.update(ctx, zone, r, r.Content, r.TTL, !on, r.Description)
}
func (p *provider) BatchFields() []string { return []string{"status", "remark"} }
func (p *provider) BatchAttribute(ctx context.Context, zone, id, field string) (string, error) {
	r, err := p.current(ctx, zone, id)
	if err != nil {
		return "", err
	}
	switch field {
	case "status":
		return r.Status, nil
	case "remark":
		return r.Description, nil
	}
	return "", dns.ErrInvalidDNSRequest
}
func (p *provider) SetBatchAttribute(ctx context.Context, zone, id, field, value string) error {
	r, err := p.current(ctx, zone, id)
	if err != nil {
		return err
	}
	switch field {
	case "status":
		if !slices.Contains([]string{"enabled", "disabled"}, value) {
			return dns.ErrInvalidDNSRequest
		}
		r.Status = value
	case "remark":
		r.Description = value
	default:
		return dns.ErrInvalidDNSRequest
	}
	_, err = p.update(ctx, zone, r, r.Content, r.TTL, r.Status == "disabled", r.Description)
	return err
}
