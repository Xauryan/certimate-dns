// Package huawei manages public Huawei Cloud DNS zones and record sets.
package huawei

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/signer"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/request"
)

var failure = errors.New("Huawei Cloud DNS request failed; refresh before retrying a change")
var validID = regexp.MustCompile("^[a-zA-Z0-9_-]{1,128}$")

type provider struct {
	ak, sk, project string
	client          *http.Client
}

func New(a *domain.Access) (dns.Provider, error) {
	ak, sk := dnsutil.Field(a, "accessKeyId"), dnsutil.Field(a, "secretAccessKey")
	if ak == "" || sk == "" {
		return nil, domain.ErrInvalidParams
	}
	return &provider{ak, sk, dnsutil.Field(a, "enterpriseProjectId"), dnsutil.HTTPClientFor(a)}, nil
}

// The SDK's signing and serialization functions share one request object.
// Attaching the caller context to the resulting HTTP request also cancels writes.
func (p *provider) call(ctx context.Context, method, path string, query map[string]string, body, out any) error {
	const host = "dns.myhuaweicloud.com"
	builder := request.NewHttpRequestBuilder().WithEndpoint("https://"+host).WithPath(path).WithMethod(method).
		AddHeaderParam("host", host).AddHeaderParam("Content-Type", "application/json").WithBody("application/json", body)
	for k, v := range query {
		builder.AddQueryParam(k, reflect.ValueOf(v))
	}
	signed := builder.Build()
	headers, err := signer.Sign(signed, p.ak, p.sk)
	if err != nil {
		return failure
	}
	for k, v := range headers {
		signed.AddHeaderParam(k, v)
	}
	req, err := signed.ConvertRequest()
	if err != nil {
		return failure
	}
	b, err := dnsutil.ReadResponse(p.client, req.WithContext(ctx))
	if err != nil {
		return err
	}
	if out != nil && json.Unmarshal(b, out) != nil {
		return failure
	}
	return nil
}

type zoneInfo struct {
	ID, Name, Status string
	Project          string `json:"enterprise_project_id"`
	ZoneType         string `json:"zone_type"`
}
type metadata struct {
	Total *int `json:"total_count"`
}

func pagination(page int) map[string]string {
	return map[string]string{"offset": strconv.Itoa((page - 1) * dns.DNSPageSize), "limit": strconv.Itoa(dns.DNSPageSize)}
}
func (p *provider) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	q := pagination(page)
	q["type"] = "public"
	if p.project != "" {
		q["enterprise_project_id"] = p.project
	}
	var out struct {
		Zones    []zoneInfo
		Metadata metadata
	}
	if err := p.call(ctx, http.MethodGet, "/v2/zones", q, nil, &out); err != nil {
		return nil, err
	}
	if out.Metadata.Total == nil || *out.Metadata.Total < 0 || len(out.Zones) != min(dns.DNSPageSize, max(0, *out.Metadata.Total-(page-1)*dns.DNSPageSize)) {
		return nil, failure
	}
	result := dnsutil.Page[dns.Zone](page, *out.Metadata.Total)
	for _, z := range out.Zones {
		if !validID.MatchString(z.ID) || z.Name == "" || !strings.EqualFold(z.ZoneType, "public") || p.project != "" && z.Project != p.project {
			return nil, failure
		}
		result.Items = append(result.Items, dns.Zone{ID: z.ID, Name: strings.TrimSuffix(z.Name, "."), Status: z.Status})
	}
	return result, nil
}

func (p *provider) zone(ctx context.Context, id string) (*zoneInfo, error) {
	if !validID.MatchString(id) {
		return nil, dns.ErrInvalidDNSRequest
	}
	var z zoneInfo
	if err := p.call(ctx, http.MethodGet, "/v2/zones/"+id, nil, nil, &z); err != nil {
		return nil, err
	}
	if z.ID != id || z.Name == "" || !strings.EqualFold(z.ZoneType, "public") || (p.project != "" && z.Project != p.project) {
		return nil, domain.ErrRecordNotFound
	}
	return &z, nil
}

type record struct {
	ID, Name, Description, Type, Line, Status string
	Zone                                      string `json:"zone_id"`
	ZoneName                                  string `json:"zone_name"`
	TTL                                       int
	Weight                                    *int
	Default                                   *bool
	Records                                   []string
	HealthCheck                               string `json:"health_check_id"`
	Alias                                     *struct {
		Target string `json:"resource_domain_name"`
	} `json:"alias_target"`
	Bundle string
}

func (r record) readOnly() bool {
	return len(r.Records) == 0 || r.Default == nil || *r.Default || r.Alias != nil || r.HealthCheck != "" || r.Bundle != "" || r.Type == "SOA"
}
func (r record) row() dns.DNSRecord {
	value := strings.Join(r.Records, "\n")
	if r.Alias != nil {
		value = r.Alias.Target
	}
	return dns.DNSRecord{Priority: dnsutil.MXPriority(r.Type, value), ID: r.ID, Name: strings.TrimSuffix(r.Name, "."), Type: r.Type, TTL: r.TTL, Content: value, Line: r.Line, Status: r.Status, Weight: r.Weight, Description: r.Description, ReadOnly: r.readOnly()}
}
func collection(zone string) string { return "/v2.1/zones/" + zone + "/recordsets" }
func (p *provider) DNSRecords(ctx context.Context, zone string, page int, filter string) (*dns.DNSPage[dns.DNSRecord], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	z, err := p.zone(ctx, zone)
	if err != nil {
		return nil, err
	}
	q := pagination(page)
	if filter != "" {
		q["name"] = filter
	}
	var out struct {
		Recordsets []record
		Metadata   metadata
	}
	if err := p.call(ctx, http.MethodGet, collection(zone), q, nil, &out); err != nil {
		return nil, err
	}
	if out.Metadata.Total == nil || *out.Metadata.Total < 0 || len(out.Recordsets) != min(dns.DNSPageSize, max(0, *out.Metadata.Total-(page-1)*dns.DNSPageSize)) {
		return nil, failure
	}
	result := dnsutil.Page[dns.DNSRecord](page, *out.Metadata.Total)
	for _, r := range out.Recordsets {
		if _, err := dnsutil.RelativeName(r.Name, z.Name); err != nil || !validID.MatchString(r.ID) || r.Type == "" || r.Zone != z.ID || !strings.EqualFold(r.ZoneName, z.Name) {
			return nil, failure
		}
		result.Items = append(result.Items, r.row())
	}
	return result, nil
}

func (p *provider) current(ctx context.Context, zone, id string) (*record, error) {
	if !validID.MatchString(id) {
		return nil, dns.ErrInvalidDNSRequest
	}
	z, err := p.zone(ctx, zone)
	if err != nil {
		return nil, err
	}
	var r record
	if err := p.call(ctx, http.MethodGet, collection(zone)+"/"+id, nil, nil, &r); err != nil {
		return nil, err
	}
	if _, err := dnsutil.RelativeName(r.Name, z.Name); err != nil || r.ID != id || r.Type == "" || r.Zone != zone || !strings.EqualFold(r.ZoneName, z.Name) {
		return nil, domain.ErrRecordNotFound
	}
	return &r, nil
}

func rdata(typ, value string) string {
	if typ == "TXT" && !strings.HasPrefix(value, `"`) {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
	}
	return value
}

func (p *provider) CreateDNSRecord(ctx context.Context, zone string, in dns.RecordInput) (string, error) {
	if in.Content == "" {
		return "", dns.ErrInvalidDNSRequest
	}
	var err error
	in.Content, err = dnsutil.MXValue(in.Type, in.Content, in.Priority, "")
	if err != nil {
		return "", err
	}
	return p.create(ctx, zone, in, []string{rdata(in.Type, in.Content)})
}
func (p *provider) create(ctx context.Context, zone string, in dns.RecordInput, values []string) (string, error) {
	if in.TTL < 1 || in.Type == "" || in.Type == "SOA" {
		return "", dns.ErrInvalidDNSRequest
	}
	z, err := p.zone(ctx, zone)
	if err != nil {
		return "", err
	}
	host, err := dnsutil.RelativeName(in.Name, z.Name)
	if err != nil {
		return "", err
	}
	body := map[string]any{"name": dnsutil.FullName(host, z.Name) + ".", "type": in.Type, "records": values, "ttl": in.TTL}
	if in.Description != "" {
		body["description"] = in.Description
	}
	if in.Weight != nil {
		if *in.Weight < 0 || *in.Weight > 1000 {
			return "", dns.ErrInvalidDNSRequest
		}
		body["weight"] = *in.Weight
	}
	if in.Line != "" {
		body["line"] = in.Line
	}
	var out record
	if err := p.call(ctx, http.MethodPost, collection(zone), nil, body, &out); err != nil {
		return "", err
	}
	if out.ID == "" || out.Zone != zone {
		return "", failure
	}
	return out.ID, nil
}
func (p *provider) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	if in.TTL < 1 || in.Content == "" {
		return "", dns.ErrInvalidDNSRequest
	}
	r, err := p.current(ctx, zone, id)
	if err != nil {
		return "", err
	}
	if r.readOnly() {
		return "", dns.ErrInvalidDNSRequest
	}
	// On v2.1 PUT, omitted description, weight and line retain their values.
	values := strings.Split(in.Content, "\n")
	if len(values) != len(r.Records) {
		return "", dns.ErrInvalidDNSRequest
	}
	oldValues := make(map[string]bool, len(r.Records))
	for _, v := range r.Records {
		oldValues[v] = true
	}
	newValues := map[string]bool{}
	changes := 0
	for i, v := range values {
		v, err := dnsutil.MXValue(r.Type, v, nil, r.Records[i])
		if err != nil {
			return "", err
		}
		value := rdata(r.Type, v)
		if v == "" || newValues[value] {
			return "", dns.ErrInvalidDNSRequest
		}
		newValues[value] = true
		if !oldValues[value] {
			changes++
		}
		values[i] = value
	}
	if len(values) > 1 && (changes > 1 || r.TTL != in.TTL) {
		return "", dns.ErrInvalidDNSRequest
	}
	return p.update(ctx, r, map[string]any{"records": values, "ttl": in.TTL})
}
func (p *provider) update(ctx context.Context, r *record, body map[string]any) (string, error) {
	id, zone := r.ID, r.Zone
	body["name"], body["type"] = r.Name, r.Type
	var out record
	if err := p.call(ctx, http.MethodPut, collection(zone)+"/"+id, nil, body, &out); err != nil {
		return "", err
	}
	if out.ID != id || out.Zone != zone {
		return "", failure
	}
	return id, nil
}
func (p *provider) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	r, err := p.current(ctx, zone, id)
	if err != nil {
		return "", err
	}
	if r.readOnly() || len(r.Records) != 1 {
		return "", dns.ErrInvalidDNSRequest
	}
	if err := p.call(ctx, http.MethodDelete, collection(zone)+"/"+id, nil, nil, nil); err != nil {
		return "", err
	}
	return id, nil
}

func (p *provider) SetRankedAddresses(ctx context.Context, zone, id string, in dns.RecordInput, values []string) (string, error) {
	if len(values) == 0 || in.TTL < 1 || (in.Type != "A" && in.Type != "AAAA") {
		return "", dns.ErrInvalidDNSRequest
	}
	seen := map[netip.Addr]bool{}
	for _, value := range values {
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.Zone() != "" || ip.Is4In6() || (in.Type == "A") != ip.Is4() || seen[ip] {
			return "", dns.ErrInvalidDNSRequest
		}
		seen[ip] = true
	}
	if id == "" {
		return p.create(ctx, zone, in, values)
	}
	r, err := p.current(ctx, zone, id)
	if err != nil {
		return "", err
	}
	if r.readOnly() || !strings.EqualFold(strings.TrimSuffix(r.Name, "."), strings.TrimSuffix(in.Name, ".")) || r.Type != in.Type || r.Line != in.Line {
		return "", dns.ErrInvalidDNSRequest
	}
	return p.update(ctx, r, map[string]any{"records": values, "ttl": in.TTL})
}

func (p *provider) CreateZone(ctx context.Context, raw string) (*dns.Zone, error) {
	name, err := dnsutil.ZoneName(raw)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"name": name + ".", "zone_type": "public"}
	if p.project != "" {
		body["enterprise_project_id"] = p.project
	}
	var z zoneInfo
	if err := p.call(ctx, http.MethodPost, "/v2/zones", nil, body, &z); err != nil {
		return nil, err
	}
	if !validID.MatchString(z.ID) || !strings.EqualFold(strings.TrimSuffix(z.Name, "."), name) || !strings.EqualFold(z.ZoneType, "public") || p.project != "" && p.project != z.Project {
		return nil, failure
	}
	return &dns.Zone{ID: z.ID, Name: name, Status: z.Status}, nil
}

func (p *provider) ZoneDetails(ctx context.Context, id string) (*dns.ZoneDetails, error) {
	z, err := p.zone(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &dns.ZoneDetails{Name: strings.TrimSuffix(z.Name, "."), Status: z.Status, Lines: []dns.RecordLine{}}
	seen := map[string]bool{}
	for {
		var page struct {
			Lines []struct {
				Line string
				Name string `json:"line_name"`
			}
			Metadata metadata
		}
		q := map[string]string{"limit": "500", "offset": strconv.Itoa(len(seen))}
		if err := p.call(ctx, http.MethodGet, "/v2.1/zones/"+id+"/lines", q, nil, &page); err != nil {
			return nil, err
		}
		if page.Metadata.Total == nil || *page.Metadata.Total < 0 {
			return nil, failure
		}
		for _, line := range page.Lines {
			if line.Line == "" || seen[line.Line] {
				return nil, failure
			}
			seen[line.Line] = true
			out.Lines = append(out.Lines, dns.RecordLine{ID: line.Line, Name: line.Name})
		}
		if len(seen) == *page.Metadata.Total {
			break
		}
		if len(page.Lines) == 0 || len(seen) > *page.Metadata.Total {
			return nil, failure
		}
	}
	return out, nil
}

func (p *provider) SetDNSRecordStatus(ctx context.Context, zone, id string, on bool) (string, error) {
	r, err := p.current(ctx, zone, id)
	if err != nil {
		return "", err
	}
	if r.readOnly() {
		return "", dns.ErrInvalidDNSRequest
	}
	status := "DISABLE"
	if on {
		status = "ENABLE"
	}
	var out record
	if err := p.call(ctx, http.MethodPut, "/v2.1/recordsets/"+id+"/statuses/set", nil, map[string]string{"status": status}, &out); err != nil {
		return "", err
	}
	if out.ID != id || out.Zone != zone {
		return "", failure
	}
	return id, nil
}

func (p *provider) BatchFields() []string { return []string{"status", "remark", "weight"} }
func (p *provider) BatchAttribute(ctx context.Context, zone, id, field string) (string, error) {
	r, err := p.current(ctx, zone, id)
	if err != nil {
		return "", err
	}
	if r.readOnly() {
		return "", dns.ErrInvalidDNSRequest
	}
	switch field {
	case "remark":
		return r.Description, nil
	case "weight":
		if r.Weight != nil {
			return strconv.Itoa(*r.Weight), nil
		}
		return "", nil
	case "status":
		switch r.Status {
		case "ACTIVE":
			return "enabled", nil
		case "DISABLE":
			return "disabled", nil
		}
	}
	return "", dns.ErrInvalidDNSRequest
}
func (p *provider) SetBatchAttribute(ctx context.Context, zone, id, field, value string) error {
	if field == "status" {
		if value != "enabled" && value != "disabled" {
			return dns.ErrInvalidDNSRequest
		}
		_, err := p.SetDNSRecordStatus(ctx, zone, id, value == "enabled")
		return err
	}
	r, err := p.current(ctx, zone, id)
	if err != nil {
		return err
	}
	if r.readOnly() {
		return dns.ErrInvalidDNSRequest
	}
	var body map[string]any
	switch field {
	case "remark":
		body = map[string]any{"description": value}
	case "weight":
		n, e := strconv.Atoi(value)
		if e != nil || n < 0 || n > 1000 {
			return dns.ErrInvalidDNSRequest
		}
		body = map[string]any{"weight": n}
	default:
		return dns.ErrInvalidDNSRequest
	}
	_, err = p.update(ctx, r, body)
	return err
}
