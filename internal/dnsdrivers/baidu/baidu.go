// Package baidu manages Baidu Cloud public DNS records.
package baidu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/baidubce/bce-sdk-go/util"
	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

const zonePath = "/v1/dns/zone"

var validID = regexp.MustCompile("^[a-zA-Z0-9_-]{1,128}$")
var failure = errors.New("Baidu DNS request failed; refresh before retrying a change")

type provider struct {
	ak, sk string
	client *http.Client
}

func New(a *domain.Access) (dns.Provider, error) {
	ak, sk := dnsutil.Field(a, "accessKeyId"), dnsutil.Field(a, "secretAccessKey")
	if strings.TrimSpace(ak) == "" || strings.TrimSpace(sk) == "" {
		return nil, domain.ErrInvalidParams
	}
	return &provider{ak, sk, dnsutil.HTTPClientFor(a)}, nil
}

// Sign host and x-bce-date with the SDK's canonical encoding and HMAC primitives.
// The full SDK signer's informational log includes the Authorization header.
func (p *provider) call(ctx context.Context, method, path string, q url.Values, body, out any) error {
	const host = "dns.baidubce.com"
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return failure
		}
	}
	if method != http.MethodGet {
		if q == nil {
			q = url.Values{}
		}
		q.Set("clientToken", util.NewRequestId())
	}
	canonicalQuery := strings.ReplaceAll(q.Encode(), "+", "%20")
	u := url.URL{Scheme: "https", Host: host, Path: path, RawQuery: canonicalQuery}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(payload))
	if err != nil {
		return failure
	}
	date := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	headers := "host:" + host + "\nx-bce-date:" + util.UriEncode(date, true)
	signedHeaders := "host;x-bce-date"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		headers = "content-type:application%2Fjson\n" + headers
		signedHeaders = "content-type;" + signedHeaders
	}
	req.Header.Set("x-bce-date", date)
	prefix := "bce-auth-v1/" + p.ak + "/" + date + "/1800"
	canonical := strings.Join([]string{method, util.UriEncode(path, false), canonicalQuery, headers}, "\n")
	signature := util.HmacSha256Hex(util.HmacSha256Hex(p.sk, prefix), canonical)
	req.Header.Set("Authorization", prefix+"/"+signedHeaders+"/"+signature)
	b, err := dnsutil.ReadResponse(p.client, req)
	if err != nil {
		return err
	}
	if out != nil && json.Unmarshal(b, out) != nil {
		return failure
	}
	return nil
}

type cursor struct {
	IsTruncated *bool
	NextMarker  string
}

// Baidu returns a marker instead of a total. Follow each marker once before
// applying client-side search and slicing the requested page.
func pages(fetch func(string) (cursor, error)) error {
	marker := ""
	seen := map[string]bool{}
	for {
		c, err := fetch(marker)
		if err != nil {
			return err
		}
		if c.IsTruncated == nil {
			return failure
		}
		if !*c.IsTruncated {
			return nil
		}
		if c.NextMarker == "" || seen[c.NextMarker] {
			return failure
		}
		marker = c.NextMarker
		seen[marker] = true
	}
}
func query(marker string) url.Values {
	q := url.Values{"maxKeys": {"1000"}}
	if marker != "" {
		q.Set("marker", marker)
	}
	return q
}

type zone struct{ Name, Status, ProductVersion string }

func (p *provider) zones(ctx context.Context, name string) ([]zone, error) {
	var zones []zone
	seen := make(map[string]bool)
	err := pages(func(marker string) (cursor, error) {
		var out struct {
			cursor
			Zones []zone
		}
		q := query(marker)
		if name != "" {
			q.Set("name", name)
		}
		if err := p.call(ctx, http.MethodGet, zonePath, q, nil, &out); err != nil {
			return cursor{}, err
		}
		if out.Zones == nil {
			return cursor{}, failure
		}
		for _, row := range out.Zones {
			z, err := dnsutil.ZoneName(row.Name)
			if err != nil || seen[z] {
				return cursor{}, failure
			}
			seen[z] = true
			row.Name = z
			zones = append(zones, row)
		}
		return out.cursor, nil
	})
	return zones, err
}

func (p *provider) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	rows, err := p.zones(ctx, "")
	if err != nil {
		return nil, err
	}
	zones := make([]dns.Zone, 0, len(rows))
	for _, row := range rows {
		// Baidu's record endpoints take the zone name rather than its inventory ID.
		zones = append(zones, dns.Zone{ID: row.Name, Name: row.Name, Status: row.Status})
	}
	return dnsutil.SlicePage(zones, page)
}

func (p *provider) ZoneDetails(ctx context.Context, zoneID string) (*dns.ZoneDetails, error) {
	z, err := dnsutil.ZoneName(zoneID)
	if err != nil {
		return nil, err
	}
	rows, err := p.zones(ctx, z)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.Name == z {
			return &dns.ZoneDetails{Name: z, Status: row.Status, Plan: row.ProductVersion, MinTTL: map[string]int{"free": 300, "discount": 120, "flagship": 1}[row.ProductVersion], Lines: []dns.RecordLine{
				{ID: "default", Name: "默认"}, {ID: "ct", Name: "电信"}, {ID: "cnc", Name: "联通"}, {ID: "cmnet", Name: "移动"}, {ID: "edu", Name: "教育网"}, {ID: "search", Name: "搜索引擎(百度)"},
			}}, nil
		}
	}
	return nil, domain.ErrRecordNotFound
}

func (p *provider) CreateZone(ctx context.Context, name string) (*dns.Zone, error) {
	z, err := dnsutil.ZoneName(name)
	if err != nil {
		return nil, err
	}
	if err := p.call(ctx, http.MethodPost, zonePath, nil, map[string]string{"name": z}, nil); err != nil {
		return nil, err
	}
	row, err := p.ZoneDetails(ctx, z)
	if err != nil {
		return nil, err
	}
	return &dns.Zone{ID: z, Name: z, Status: row.Status}, nil
}

type record struct {
	ID, Name, Rr, Status, Type, Value, Line, Description string
	ZoneName                                             string `json:"zone_name"`
	TTL                                                  int
	Priority                                             *int
}

func collection(zone string) string { return zonePath + "/" + zone + "/record" }
func (p *provider) records(ctx context.Context, zone, rr, id string) ([]record, error) {
	var records []record
	seen := make(map[string]bool)
	err := pages(func(marker string) (cursor, error) {
		var out struct {
			cursor
			Records []record
		}
		q := query(marker)
		if rr != "" {
			q.Set("rr", rr)
		}
		if id != "" {
			q.Set("id", id)
		}
		if err := p.call(ctx, http.MethodGet, collection(zone), q, nil, &out); err != nil {
			return cursor{}, err
		}
		if out.Records == nil {
			return cursor{}, failure
		}
		for _, row := range out.Records {
			if !validID.MatchString(row.ID) || seen[row.ID] || row.Type == "" || row.TTL < 1 || row.Value == "" {
				return cursor{}, failure
			}
			if row.ZoneName != "" {
				z, err := dnsutil.ZoneName(row.ZoneName)
				if err != nil || z != zone {
					return cursor{}, failure
				}
			}
			// ID-filtered responses can use the full name rather than rr.
			if row.Name != "" {
				host, err := dnsutil.RelativeName(row.Name, zone)
				if err != nil || (row.Rr != "" && !strings.EqualFold(row.Rr, host)) {
					return cursor{}, failure
				}
				row.Rr = host
			}
			if row.Rr == "" {
				return cursor{}, failure
			}
			if _, err := dnsutil.RelativeName(dnsutil.FullName(row.Rr, zone), zone); err != nil {
				return cursor{}, failure
			}
			seen[row.ID] = true
			records = append(records, row)
		}
		return out.cursor, nil
	})
	return records, err
}

func (p *provider) DNSRecords(ctx context.Context, zone string, page int, filter string) (*dns.DNSPage[dns.DNSRecord], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return nil, err
	}
	records, err := p.records(ctx, z, "", "")
	if err != nil {
		return nil, err
	}
	var rows []dns.DNSRecord
	for _, r := range records {
		name := dnsutil.FullName(r.Rr, z)
		if !strings.Contains(strings.ToLower(name), strings.ToLower(filter)) && !strings.Contains(strings.ToLower(r.Value), strings.ToLower(filter)) {
			continue
		}
		rows = append(rows, dns.DNSRecord{ID: r.ID, Name: name, Type: r.Type, Content: r.Value, TTL: r.TTL, Line: r.Line, Status: r.Status, Description: r.Description, Priority: r.Priority})
	}
	return dnsutil.SlicePage(rows, page)
}

func (p *provider) current(ctx context.Context, zone, id string) (string, *record, error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", nil, err
	}
	if !validID.MatchString(id) {
		return "", nil, dns.ErrInvalidDNSRequest
	}
	items, err := p.records(ctx, z, "", id)
	if err != nil {
		return "", nil, err
	}
	for _, r := range items {
		if r.ID == id {
			return z, &r, nil
		}
	}
	return "", nil, domain.ErrRecordNotFound
}

func (p *provider) CreateDNSRecord(ctx context.Context, zone string, in dns.RecordInput) (string, error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", err
	}
	host, err := dnsutil.RelativeName(in.Name, z)
	if err != nil {
		return "", err
	}
	switch in.Type {
	case "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV":
	default:
		return "", dns.ErrInvalidDNSRequest
	}
	if in.TTL < 1 || in.TTL > math.MaxInt32 || in.Content == "" || in.Weight != nil || utf8.RuneCountInString(in.Description) > 255 || (in.Priority != nil && (in.Type != "MX" || *in.Priority < 0 || *in.Priority > 50)) {
		return "", dns.ErrInvalidDNSRequest
	}
	line := in.Line
	if line == "" {
		line = "default"
	}
	body := map[string]any{"rr": host, "type": in.Type, "value": in.Content, "ttl": in.TTL, "line": line}
	if in.Description != "" {
		body["description"] = in.Description
	}
	priority := 1
	if in.Type == "MX" {
		in.Content, priority, err = dnsutil.MXParts(in.Content, in.Priority, 1, 50)
		if err != nil {
			return "", err
		}
		body["priority"], body["value"] = priority, in.Content
	}
	if err := p.call(ctx, http.MethodPost, collection(z), nil, body, nil); err != nil {
		return "", err
	}
	// The create response has no record ID. Confirm the exact record on its line.
	items, err := p.records(ctx, z, host, "")
	if err != nil {
		return "", err
	}
	id := ""
	for _, r := range items {
		if r.Type == "MX" && (r.Priority == nil || *r.Priority != priority) {
			continue
		}
		if strings.EqualFold(r.Rr, host) && r.Type == in.Type && r.Value == in.Content && r.Line == line && r.TTL == in.TTL && r.Description == in.Description {
			if id != "" {
				return "", failure
			}
			id = r.ID
		}
	}
	if id == "" {
		return "", failure
	}
	return id, nil
}

func (p *provider) update(ctx context.Context, z string, r record) error {
	// Line and status are not writable on the update-record endpoint.
	body := map[string]any{"rr": r.Rr, "type": r.Type, "value": r.Value, "ttl": r.TTL, "description": r.Description}
	if r.Type == "MX" {
		if r.Priority == nil {
			return failure
		}
		body["priority"] = *r.Priority
	}
	return p.call(ctx, http.MethodPut, collection(z)+"/"+r.ID, nil, body, nil)
}

func (p *provider) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	if in.TTL < 1 || in.TTL > math.MaxInt32 || in.Content == "" {
		return "", dns.ErrInvalidDNSRequest
	}
	z, r, err := p.current(ctx, zone, id)
	if err != nil {
		return "", err
	}
	if r.Type == "MX" {
		if r.Priority == nil {
			return "", failure
		}
		target, priority, err := dnsutil.MXParts(in.Content, nil, *r.Priority, 50)
		if err != nil {
			return "", err
		}
		r.Priority, in.Content = &priority, target
	}
	r.Value, r.TTL = in.Content, in.TTL
	if err := p.update(ctx, z, *r); err != nil {
		return "", err
	}
	return id, nil
}
func (p *provider) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	z, _, err := p.current(ctx, zone, id)
	if err != nil {
		return "", err
	}
	if err := p.call(ctx, http.MethodDelete, collection(z)+"/"+id, nil, nil, nil); err != nil {
		return "", err
	}
	return id, nil
}

func (p *provider) BatchFields() []string { return []string{"remark", "status"} }
func (p *provider) BatchAttribute(ctx context.Context, zone, id, field string) (string, error) {
	_, r, err := p.current(ctx, zone, id)
	if err != nil {
		return "", err
	}
	switch field {
	case "remark":
		return r.Description, nil
	case "status":
		switch r.Status {
		case "running":
			return "enabled", nil
		case "stopped":
			return "disabled", nil
		}
	}
	return "", dns.ErrInvalidDNSRequest
}
func (p *provider) SetBatchAttribute(ctx context.Context, zone, id, field, value string) error {
	z, r, err := p.current(ctx, zone, id)
	if err != nil {
		return err
	}
	switch field {
	case "remark":
		if utf8.RuneCountInString(value) > 255 {
			return dns.ErrInvalidDNSRequest
		}
		r.Description = value
		return p.update(ctx, z, *r)
	case "status":
		action, ok := map[string]string{"enabled": "enable", "disabled": "disable"}[value]
		if !ok {
			return dns.ErrInvalidDNSRequest
		}
		return p.call(ctx, http.MethodPut, collection(z)+"/"+id, url.Values{action: {""}}, nil, nil)
	}
	return dns.ErrInvalidDNSRequest
}
