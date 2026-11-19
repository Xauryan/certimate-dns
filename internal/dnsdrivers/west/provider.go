// Package west manages West.cn DNS through its v2 domain API.
package west

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/dnsdrivers/registrarutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	"golang.org/x/text/encoding/simplifiedchinese"
)

type provider struct {
	user, password, endpoint string
	client                   *http.Client
}

func New(a *domain.Access) (dns.Provider, error) {
	user, password := dnsutil.Field(a, "username"), dnsutil.Field(a, "apiPassword")
	if user == "" || password == "" {
		return nil, domain.ErrInvalidParams
	}
	return &provider{user, password, "https://api.west.cn/api/v2/domain/", dnsutil.HTTPClientFor(a)}, nil
}

var errResponse = errors.New("invalid West.cn DNS response")

func (p *provider) call(ctx context.Context, form url.Values, dest any) error {
	stamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	digest := md5.Sum([]byte(p.user + p.password + stamp)) // Required by the West.cn v2 signing protocol.
	form.Set("token", hex.EncodeToString(digest[:]))
	form.Set("username", p.user)
	form.Set("time", stamp)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return errResponse
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	body, err := dnsutil.ReadResponse(p.client, req)
	if err != nil {
		return err
	}
	if !utf8.Valid(body) {
		body, err = simplifiedchinese.GBK.NewDecoder().Bytes(body)
		if err != nil {
			return errResponse
		}
	}
	var env struct {
		Result json.Number
		Data   json.RawMessage
	}
	if json.Unmarshal(body, &env) != nil || env.Result.String() != "200" {
		return errResponse
	}
	if dest != nil && (len(env.Data) == 0 || string(env.Data) == "null" || json.Unmarshal(env.Data, dest) != nil) {
		return errResponse
	}
	return nil
}

func (p *provider) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	var data struct {
		Total json.Number
		Items []struct{ Domain string }
	}
	err := p.call(ctx, url.Values{"act": {"getdomains"}, "page": {strconv.Itoa(page)}, "limit": {strconv.Itoa(dns.DNSPageSize)}}, &data)
	if err != nil {
		return nil, err
	}
	total, err := strconv.Atoi(data.Total.String())
	if err != nil || data.Items == nil || !registrarutil.CompletePage(total, (page-1)*dns.DNSPageSize, dns.DNSPageSize, len(data.Items)) {
		return nil, errResponse
	}
	out := dnsutil.Page[dns.Zone](page, total)
	for _, row := range data.Items {
		name, err := dnsutil.ZoneName(row.Domain)
		if err != nil {
			return nil, errResponse
		}
		out.Items = append(out.Items, dns.Zone{ID: name, Name: name})
	}
	return out, nil
}

type record struct {
	ID, TTL, Level, Pause   json.Number
	Item, Type, Value, Line string
}

func (p *provider) records(ctx context.Context, z string, page int, filter string) ([]record, int, error) {
	var data struct {
		Total json.Number
		Items []record
	}
	form := url.Values{"act": {"getdnsrecord"}, "domain": {z}, "pageno": {strconv.Itoa(page)}, "limit": {strconv.Itoa(dns.DNSPageSize)}}
	if filter != "" {
		if label, err := dnsutil.RelativeName(filter, z); err == nil {
			filter = label
		}
		form.Set("host", filter)
	}
	if err := p.call(ctx, form, &data); err != nil {
		return nil, 0, err
	}
	total, err := strconv.Atoi(data.Total.String())
	if err != nil || data.Items == nil || !registrarutil.CompletePage(total, (page-1)*dns.DNSPageSize, dns.DNSPageSize, len(data.Items)) {
		return nil, 0, errResponse
	}
	for _, r := range data.Items {
		if _, err := dnsutil.PositiveID(r.ID.String()); err != nil || r.TTL == "" || r.Type == "" || r.Item == "" {
			return nil, 0, errResponse
		}
	}
	return data.Items, total, nil
}
func (p *provider) DNSRecords(ctx context.Context, zone string, page int, filter string) (*dns.DNSPage[dns.DNSRecord], error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil || !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	items, total, err := p.records(ctx, z, page, filter)
	if err != nil {
		return nil, err
	}
	out := dnsutil.Page[dns.DNSRecord](page, total)
	for _, r := range items {
		ttl, err := strconv.Atoi(r.TTL.String())
		if err != nil || r.ID == "" || r.Type == "" {
			return nil, errResponse
		}
		status := "enabled"
		if r.Pause.String() == "1" {
			status = "disabled"
		}
		content := r.Value
		if r.Type == "MX" {
			if r.Level == "" {
				return nil, errResponse
			}
			content = r.Level.String() + " " + r.Value
		}
		out.Items = append(out.Items, dns.DNSRecord{ID: r.ID.String(), Name: dnsutil.FullName(r.Item, z), Type: r.Type, Priority: dnsutil.MXPriority(r.Type, content), Content: content, Line: r.Line, TTL: ttl, Status: status})
	}
	return out, nil
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
	if in.Type == "MX" {
		in.Content, err = dnsutil.MXValue(in.Type, in.Content, in.Priority, "")
		if err != nil {
			return "", err
		}
	}
	form := url.Values{"act": {"adddnsrecord"}, "domain": {z}, "host": {host}, "type": {in.Type}, "value": {in.Content}, "ttl": {strconv.Itoa(in.TTL)}, "line": {wireLine(in.Line)}}
	if err := setValue(form, in.Type, in.Content, in.TTL); err != nil {
		return "", err
	}
	var data struct{ ID json.Number }
	if err := p.call(ctx, form, &data); err != nil {
		return "", err
	}
	if _, err := dnsutil.PositiveID(data.ID.String()); err != nil {
		return "", errResponse
	}
	return data.ID.String(), nil
}

func wireLine(line string) string {
	if line == "default" || line == "0" {
		return ""
	}
	return line
}
func setValue(form url.Values, typ, content string, ttl int) error {
	if typ == "" || content == "" || ttl < 1 {
		return dns.ErrInvalidDNSRequest
	}
	if typ == "MX" {
		priority, exchange, err := registrarutil.ParseMX(content)
		if err != nil {
			return err
		}
		form.Set("level", strconv.Itoa(priority))
		form.Set("value", exchange)
	}
	return nil
}
func (p *provider) find(ctx context.Context, z, id string) (record, error) {
	if _, err := dnsutil.PositiveID(id); err != nil {
		return record{}, err
	}
	var found record
	err := registrarutil.Walk(dns.DNSPageSize, func(page int) ([]record, int, error) { return p.records(ctx, z, page, "") }, func(r record) string { return r.ID.String() }, func(r record) error {
		if r.ID.String() == id {
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

func updateForm(zone string, r record) url.Values {
	form := url.Values{"act": {"moddnsrecord"}, "domain": {zone}, "id": {r.ID.String()}, "type": {r.Type}, "value": {r.Value}, "ttl": {r.TTL.String()}, "line": {r.Line}}
	if r.Level != "" {
		form.Set("level", r.Level.String())
	}
	return form
}

func (p *provider) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", err
	}
	r, err := p.find(ctx, z, id)
	if err != nil {
		return "", err
	}
	in.Content, err = dnsutil.MXValue(r.Type, in.Content, nil, r.Level.String()+" "+r.Value)
	if err != nil {
		return "", err
	}
	form := updateForm(z, r)
	form.Set("value", in.Content)
	form.Set("ttl", strconv.Itoa(in.TTL))
	if err := setValue(form, r.Type, in.Content, in.TTL); err != nil {
		return "", err
	}
	if err := p.call(ctx, form, nil); err != nil {
		return "", err
	}
	return id, nil
}

func (p *provider) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", err
	}
	if _, err := p.find(ctx, z, id); err != nil {
		return "", err
	}
	if err := p.call(ctx, url.Values{"act": {"deldnsrecord"}, "domain": {z}, "id": {id}}, nil); err != nil {
		return "", err
	}
	return id, nil
}

func (p *provider) BatchFields() []string { return []string{"status", "line"} }
func (p *provider) BatchAttribute(ctx context.Context, zone, id, field string) (string, error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", err
	}
	r, err := p.find(ctx, z, id)
	if err != nil {
		return "", err
	}
	switch field {
	case "line":
		return r.Line, nil
	case "status":
		switch r.Pause.String() {
		case "1":
			return "disabled", nil
		case "0":
			return "enabled", nil
		}
		return "", errResponse
	}
	return "", dns.ErrInvalidDNSRequest
}
func (p *provider) SetBatchAttribute(ctx context.Context, zone, id, field, value string) error {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return err
	}
	r, err := p.find(ctx, z, id)
	if err != nil {
		return err
	}
	switch field {
	case "line":
		form := updateForm(z, r)
		form.Set("line", wireLine(value))
		return p.call(ctx, form, nil)
	case "status":
		var pause string
		switch value {
		case "enabled":
			pause = "0"
		case "disabled":
			pause = "1"
		default:
			return dns.ErrInvalidDNSRequest
		}
		return p.call(ctx, url.Values{"act": {"pause"}, "domain": {z}, "id": {id}, "val": {pause}}, nil)
	}
	return dns.ErrInvalidDNSRequest
}
func (p *provider) ZoneDetails(ctx context.Context, zone string) (*dns.ZoneDetails, error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return nil, err
	}
	if _, _, err := p.records(ctx, z, 1, ""); err != nil {
		return nil, err
	}
	return &dns.ZoneDetails{Name: z, Lines: []dns.RecordLine{
		{ID: "", Name: "默认"}, {ID: "LTEL", Name: "电信"}, {ID: "LCNC", Name: "联通"}, {ID: "LMOB", Name: "移动"}, {ID: "LEDU", Name: "教育网"}, {ID: "LSEO", Name: "搜索引擎"}, {ID: "LFOR", Name: "境外"},
	}}, nil
}
