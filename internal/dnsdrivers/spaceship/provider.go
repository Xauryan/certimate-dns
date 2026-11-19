// Package spaceship implements Spaceship's custom DNS resource record API.
package spaceship

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/dnsdrivers/registrarutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type provider struct{ api registrarutil.API }

func New(a *domain.Access) (dns.Provider, error) {
	key, secret := dnsutil.Field(a, "apiKey"), dnsutil.Field(a, "apiSecret")
	if key == "" || secret == "" {
		return nil, domain.ErrInvalidParams
	}
	return &provider{registrarutil.API{Base: "https://spaceship.dev/api/v1", Client: dnsutil.HTTPClientFor(a), Headers: http.Header{"X-Api-Key": {key}, "X-Api-Secret": {secret}}}}, nil
}

type list[T any] struct {
	Items []T  `json:"items"`
	Total *int `json:"total"`
}

func getPage[T any](ctx context.Context, p *provider, path string, skip, take int) (*list[T], error) {
	var out list[T]
	err := p.api.JSON(ctx, "GET", fmt.Sprintf("%s?skip=%d&take=%d", path, skip, take), nil, &out)
	if err != nil {
		return nil, err
	}
	if out.Total == nil || out.Items == nil || !registrarutil.CompletePage(*out.Total, skip, take, len(out.Items)) {
		return nil, errors.New("invalid Spaceship list response")
	}
	return &out, nil
}
func (p *provider) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	result, err := getPage[struct {
		Name   string
		Status string
	}](ctx, p, "/domains", (page-1)*dns.DNSPageSize, dns.DNSPageSize)
	if err != nil {
		return nil, err
	}
	out := dnsutil.Page[dns.Zone](page, *result.Total)
	for _, z := range result.Items {
		name, err := dnsutil.ZoneName(z.Name)
		if err != nil {
			return nil, registrarutil.ErrInventory
		}
		out.Items = append(out.Items, dns.Zone{ID: name, Name: name, Status: z.Status})
	}
	return out, nil
}

// Spaceship identifies records by their RDATA. Keep the original typed values for exact-value deletion.
type record map[string]json.RawMessage

func (r record) s(key string) string { var s string; _ = json.Unmarshal(r[key], &s); return s }
func (r record) n(key string) int    { var n int; _ = json.Unmarshal(r[key], &n); return n }

var simpleFields = map[string]string{"A": "address", "AAAA": "address", "CNAME": "cname", "TXT": "value", "NS": "nameserver", "ALIAS": "aliasName", "PTR": "pointer"}

func (r record) content() string {
	switch typ := r.s("type"); typ {
	case "MX":
		return fmt.Sprintf("%d %s", r.n("preference"), r.s("exchange"))
	case "SRV":
		return fmt.Sprintf("%d %d %d %s", r.n("priority"), r.n("weight"), r.n("port"), r.s("target"))
	case "CAA":
		return registrarutil.FormatCAA(r.n("flag"), r.s("tag"), r.s("value"))
	default:
		if field, ok := simpleFields[typ]; ok {
			return r.s(field)
		}
		// Preserve unrecognized record data for display and identity, excluding mutable metadata.
		raw := record{}
		for k, v := range r {
			if k != "name" && k != "type" && k != "ttl" && k != "group" {
				raw[k] = v
			}
		}
		data, _ := json.Marshal(raw)
		return string(data)
	}
}
func (r record) managed() bool {
	var group struct{ Type string }
	_ = json.Unmarshal(r["group"], &group)
	return group.Type != "custom"
}
func (r record) id(zone string) string {
	typ, content := r.s("type"), r.content()
	if typ != "TXT" {
		content = strings.ToLower(content)
	}
	if addr, err := netip.ParseAddr(content); (typ == "A" || typ == "AAAA") && err == nil {
		content = addr.String()
	}
	if typ == "CNAME" {
		content = strings.TrimSuffix(content, ".")
	}
	key, _ := json.Marshal([]string{zone, typ, strings.ToLower(r.s("name")), content})
	digest := sha256.Sum256(key)
	return hex.EncodeToString(digest[:])
}
func (r record) writable() (record, error) {
	fields := []string{"name", "type"}
	switch typ := r.s("type"); typ {
	case "MX":
		fields = append(fields, "preference", "exchange")
	case "SRV":
		fields = append(fields, "priority", "weight", "port", "target")
	case "CAA":
		fields = append(fields, "flag", "tag", "value")
	default:
		field, ok := simpleFields[typ]
		if !ok {
			return nil, dns.ErrInvalidDNSRequest
		}
		fields = append(fields, field)
	}
	out := record{}
	for _, k := range fields {
		if len(r[k]) == 0 {
			return nil, errors.New("invalid Spaceship record response")
		}
		out[k] = r[k]
	}
	return out, nil
}
func (p *provider) each(ctx context.Context, z string, fn func(record) error) error {
	path := "/dns/records/" + url.PathEscape(z)
	const take = 500
	return registrarutil.Walk(take, func(n int) ([]record, int, error) {
		page, err := getPage[record](ctx, p, path, (n-1)*take, take)
		if err != nil {
			return nil, 0, err
		}
		return page.Items, *page.Total, nil
	}, func(r record) string { return r.id(z) }, func(r record) error {
		if err := r.validate(z); err != nil {
			return err
		}
		return fn(r)
	})
}
func (p *provider) DNSRecords(ctx context.Context, zone string, page int, filter string) (*dns.DNSPage[dns.DNSRecord], error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return nil, err
	}
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	out := dnsutil.Page[dns.DNSRecord](page, 0)
	appendRow := func(r record) {
		name := dnsutil.FullName(r.s("name"), z)
		status := "active"
		if r.managed() {
			status = "managed"
		}
		out.Items = append(out.Items, dns.DNSRecord{ID: r.id(z), Type: r.s("type"), Priority: dnsutil.MXPriority(r.s("type"), r.content()), Name: name, Content: r.content(), TTL: r.n("ttl"), Line: "default", Status: status, ReadOnly: r.managed() || !r.supported()})
	}
	skip := (page - 1) * dns.DNSPageSize
	if filter == "" {
		rows, err := getPage[record](ctx, p, "/dns/records/"+url.PathEscape(z), skip, dns.DNSPageSize)
		if err != nil {
			return nil, err
		}
		out.Info.Total = *rows.Total
		for _, r := range rows.Items {
			if err := r.validate(z); err != nil {
				return nil, err
			}
			appendRow(r)
		}
		return out, nil
	}
	err = p.each(ctx, z, func(r record) error {
		if strings.Contains(strings.ToLower(dnsutil.FullName(r.s("name"), z)), strings.ToLower(filter)) {
			if out.Info.Total >= skip && len(out.Items) < dns.DNSPageSize {
				appendRow(r)
			}
			out.Info.Total++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (r record) supported() bool {
	switch r.s("type") {
	case "MX", "CAA", "SRV":
		return true
	}
	_, ok := simpleFields[r.s("type")]
	return ok
}
func (r record) validate(z string) error {
	if r.s("type") == "" || r.s("name") == "" || r.n("ttl") <= 0 {
		return registrarutil.ErrInventory
	}
	if _, err := dnsutil.RelativeName(dnsutil.FullName(r.s("name"), z), z); err != nil {
		return registrarutil.ErrInventory
	}
	if r.supported() {
		if _, err := r.writable(); err != nil {
			return registrarutil.ErrInventory
		}
	}
	return nil
}
func newRecord(host, typ, content string) (record, error) {
	fields := map[string]any{"name": host, "type": typ}
	if content == "" {
		return nil, dns.ErrInvalidDNSRequest
	}
	switch typ {
	case "MX":
		prio, exchange, err := registrarutil.ParseMX(content)
		if err != nil {
			return nil, err
		}
		fields["preference"], fields["exchange"] = prio, exchange
	case "SRV":
		prio, weight, port, target, err := registrarutil.ParseSRV(content)
		if err != nil {
			return nil, err
		}
		fields["priority"], fields["weight"], fields["port"], fields["target"] = prio, weight, port, target
	case "CAA":
		flag, tag, value, err := registrarutil.ParseCAA(content)
		if err != nil {
			return nil, err
		}
		fields["flag"], fields["tag"], fields["value"] = flag, tag, value
	default:
		field, ok := simpleFields[typ]
		if !ok {
			return nil, dns.ErrInvalidDNSRequest
		}
		fields[field] = content
	}
	r := record{}
	for key, v := range fields {
		r[key], _ = json.Marshal(v)
	}
	return r, nil
}
func (p *provider) save(ctx context.Context, z string, r record, ttl int) error {
	item, err := r.writable()
	if err != nil {
		return err
	}
	item["ttl"] = json.RawMessage(strconv.Itoa(ttl))
	return p.api.JSON(ctx, "PUT", "/dns/records/"+url.PathEscape(z), map[string]any{"force": false, "items": []record{item}}, nil)
}
func (p *provider) remove(ctx context.Context, z string, r record) error {
	item, err := r.writable()
	if err != nil {
		return err
	}
	return p.api.JSON(ctx, "DELETE", "/dns/records/"+url.PathEscape(z), []record{item}, nil)
}
func (p *provider) CreateDNSRecord(ctx context.Context, zone string, in dns.RecordInput) (string, error) {
	if in.Priority != nil && in.Type != "MX" || in.Description != "" || in.Weight != nil {
		return "", dns.ErrInvalidDNSRequest
	}
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", err
	}
	host, err := dnsutil.RelativeName(in.Name, z)
	if err != nil {
		return "", err
	}
	if in.TTL < 60 || in.TTL > 3600 || (in.Line != "" && in.Line != "default") {
		return "", dns.ErrInvalidDNSRequest
	}
	if in.Type == "MX" {
		in.Content, err = dnsutil.MXValue(in.Type, in.Content, in.Priority, "")
		if err != nil {
			return "", err
		}
	}
	r, err := newRecord(host, in.Type, in.Content)
	if err != nil {
		return "", err
	}
	id := r.id(z)
	err = p.each(ctx, z, func(row record) error {
		if row.id(z) == id {
			return domain.NewError(409, "Spaceship record already exists")
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if err := p.save(ctx, z, r, in.TTL); err != nil {
		return "", err
	}
	return id, nil
}

func (p *provider) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", err
	}
	if in.TTL < 60 || in.TTL > 3600 || in.Content == "" {
		return "", dns.ErrInvalidDNSRequest
	}
	var old record
	existing := make(map[string]struct{})
	err = p.each(ctx, z, func(r record) error {
		key := r.id(z)
		existing[key] = struct{}{}
		if key == id {
			old = r
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if old == nil {
		return "", domain.ErrRecordNotFound
	}
	if old.managed() {
		return "", domain.NewError(400, "Spaceship service-managed record")
	}
	in.Content, err = dnsutil.MXValue(old.s("type"), in.Content, nil, old.content())
	if err != nil {
		return "", err
	}
	next, err := newRecord(old.s("name"), old.s("type"), in.Content)
	if err != nil {
		return "", err
	}
	nextID := next.id(z)
	if nextID == id {
		return id, p.save(ctx, z, next, in.TTL)
	}
	if _, ok := existing[nextID]; ok {
		return "", domain.NewError(409, "an equivalent Spaceship record already exists")
	}
	// Spaceship can update TTL in place, but replacing RDATA requires two exact-value operations.
	// A CNAME cannot coexist with its replacement. Restore the previous value if adding the new one fails.
	if old.s("type") == "CNAME" {
		if err := p.remove(ctx, z, old); err != nil {
			return "", err
		}
		if err := p.save(ctx, z, next, in.TTL); err != nil {
			if restoreErr := p.save(ctx, z, old, old.n("ttl")); restoreErr != nil {
				return "", errors.New("Spaceship CNAME replacement interrupted; refresh to verify both values")
			}
			return "", err
		}
	} else {
		if err := p.save(ctx, z, next, in.TTL); err != nil {
			return "", err
		}
		if err := p.remove(ctx, z, old); err != nil {
			return "", errors.New("Spaceship saved the new record; refresh to verify removal of the old value")
		}
	}
	return nextID, nil
}
func (p *provider) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", err
	}
	var old record
	if err := p.each(ctx, z, func(r record) error {
		if r.id(z) == id {
			old = r
		}
		return nil
	}); err != nil {
		return "", err
	}
	if old == nil {
		return "", domain.ErrRecordNotFound
	}
	if old.managed() {
		return "", domain.NewError(400, "Spaceship service-managed record")
	}
	if err := p.remove(ctx, z, old); err != nil {
		return "", err
	}
	return id, nil
}
