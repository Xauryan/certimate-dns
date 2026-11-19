// Package huoshan manages public DNS records in Volcengine TrafficRoute.
package huoshan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	"github.com/volcengine/volc-sdk-golang/base"
)

var errResponse = errors.New("invalid Volcengine DNS response")

type provider struct {
	cred              base.Credentials
	project, endpoint string
	client            *http.Client
}

func New(a *domain.Access) (dns.Provider, error) {
	id, secret := dnsutil.Field(a, "accessKeyId"), dnsutil.Field(a, "secretAccessKey")
	if id == "" || secret == "" {
		return nil, domain.ErrInvalidParams
	}
	return &provider{base.Credentials{AccessKeyID: id, SecretAccessKey: secret, Region: "cn-beijing", Service: "dns"}, dnsutil.Field(a, "projectName"), "https://dns.volcengineapi.com/", dnsutil.HTTPClientFor(a)}, nil
}

func (p *provider) call(ctx context.Context, action string, q url.Values, input map[string]any, dest any) error {
	if q == nil {
		q = url.Values{}
	}
	q.Set("Action", action)
	q.Set("Version", "2018-08-01")
	var payload []byte
	method := http.MethodGet
	if input != nil {
		method = http.MethodPost
		if p.project != "" {
			input["ProjectName"] = p.project
		}
		var err error
		payload, err = json.Marshal(input)
		if err != nil {
			return dns.ErrInvalidDNSRequest
		}
	} else if p.project != "" {
		q.Set("ProjectName", p.project)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.endpoint+"?"+q.Encode(), bytes.NewReader(payload))
	if err != nil {
		return dns.ErrInvalidDNSRequest
	}
	req.Header.Set("Content-Type", "application/json")
	p.cred.Sign(req)
	body, err := dnsutil.ReadResponse(p.client, req)
	if err != nil {
		return err
	}
	var env struct {
		ResponseMetadata *struct {
			Error     *struct{}
			RequestID string
		}
		Result json.RawMessage
	}
	if json.Unmarshal(body, &env) != nil || env.ResponseMetadata == nil || env.ResponseMetadata.RequestID == "" || env.ResponseMetadata.Error != nil {
		return errResponse
	}
	if dest != nil && (len(env.Result) == 0 || string(env.Result) == "null" || json.Unmarshal(env.Result, dest) != nil) {
		return errResponse
	}
	return nil
}

type zoneInfo struct {
	TradeCode             string
	ZID                   int64
	ZoneName, ProjectName string
	Stage                 json.Number
}
type zoneList struct {
	Total *int
	Zones []zoneInfo
}

func (p *provider) zones(ctx context.Context, page int, key string) (*zoneList, error) {
	q := url.Values{"PageNumber": {strconv.Itoa(page)}, "PageSize": {strconv.Itoa(dns.DNSPageSize)}}
	if key != "" {
		q.Set("Key", key)
		q.Set("SearchMode", "exact")
	}
	var data zoneList
	if err := p.call(ctx, "ListZones", q, nil, &data); err != nil {
		return nil, err
	}
	if data.Total == nil || *data.Total < 0 || len(data.Zones) != min(dns.DNSPageSize, max(0, *data.Total-(page-1)*dns.DNSPageSize)) {
		return nil, errResponse
	}
	for _, v := range data.Zones {
		if v.ZID <= 0 || v.ZoneName == "" || p.project != "" && p.project != v.ProjectName {
			return nil, errResponse
		}
	}
	return &data, nil
}
func (p *provider) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	data, err := p.zones(ctx, page, "")
	if err != nil {
		return nil, err
	}
	out := dnsutil.Page[dns.Zone](page, *data.Total)
	for _, v := range data.Zones {
		name, err := dnsutil.ZoneName(v.ZoneName)
		if err != nil {
			return nil, errResponse
		}
		out.Items = append(out.Items, dns.Zone{ID: name, Name: name, Status: v.Stage.String()})
	}
	return out, nil
}
func (p *provider) zone(ctx context.Context, zone string) (string, int64, error) {
	name, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", 0, err
	}
	data, err := p.zones(ctx, 1, name)
	if err != nil {
		return "", 0, err
	}
	for _, v := range data.Zones {
		if n, e := dnsutil.ZoneName(v.ZoneName); e == nil && n == name {
			return name, v.ZID, nil
		}
	}
	return "", 0, domain.ErrRecordNotFound
}

type record struct {
	zoneID                                    int64
	Tags                                      []string
	RecordID, Host, Line, Type, Value, Remark string
	TTL                                       int
	Weight                                    *int
	Enable                                    *bool
}
type recordList struct {
	TotalCount *int
	Records    []record
}

func (p *provider) records(ctx context.Context, zid int64, page int, filter string) (*recordList, error) {
	q := url.Values{"ZID": {strconv.FormatInt(zid, 10)}, "PageNumber": {strconv.Itoa(page)}, "PageSize": {strconv.Itoa(dns.DNSPageSize)}}
	if filter != "" {
		q.Set("Host", filter)
	}
	var data recordList
	if err := p.call(ctx, "ListRecords", q, nil, &data); err != nil {
		return nil, err
	}
	if data.TotalCount == nil || *data.TotalCount < 0 || len(data.Records) != min(dns.DNSPageSize, max(0, *data.TotalCount-(page-1)*dns.DNSPageSize)) {
		return nil, errResponse
	}
	for _, r := range data.Records {
		if r.RecordID == "" || r.Type == "" || r.Host == "" || r.Line == "" || r.Value == "" || r.TTL < 1 || r.Enable == nil {
			return nil, errResponse
		}
	}
	return &data, nil
}
func (p *provider) DNSRecords(ctx context.Context, zone string, page int, filter string) (*dns.DNSPage[dns.DNSRecord], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	z, zid, err := p.zone(ctx, zone)
	if err != nil {
		return nil, err
	}
	if label, err := dnsutil.RelativeName(filter, z); err == nil {
		filter = label
	}
	data, err := p.records(ctx, zid, page, filter)
	if err != nil {
		return nil, err
	}
	out := dnsutil.Page[dns.DNSRecord](page, *data.TotalCount)
	for _, r := range data.Records {
		status := "disabled"
		if *r.Enable {
			status = "enabled"
		}
		out.Items = append(out.Items, dns.DNSRecord{Priority: dnsutil.MXPriority(r.Type, r.Value), ID: r.RecordID, Type: r.Type, Name: dnsutil.FullName(r.Host, z), Content: r.Value, TTL: r.TTL, Line: r.Line, Status: status, ReadOnly: slices.Contains(r.Tags, "GTMLock"), Weight: r.Weight, Description: r.Remark})
	}
	return out, nil
}
func (p *provider) CreateDNSRecord(ctx context.Context, zone string, in dns.RecordInput) (string, error) {
	z, zid, err := p.zone(ctx, zone)
	if err != nil {
		return "", err
	}
	host, err := dnsutil.RelativeName(in.Name, z)
	if err != nil {
		return "", err
	}
	line := in.Line
	if line == "" {
		line = "default"
	}
	if in.TTL < 1 || in.Content == "" || in.Type == "" {
		return "", dns.ErrInvalidDNSRequest
	}
	in.Content, err = dnsutil.MXValue(in.Type, in.Content, in.Priority, "")
	if err != nil {
		return "", err
	}
	if err := p.guardSiblings(ctx, zid, "", host, in.Type, line, in.TTL); err != nil {
		return "", err
	}
	input := map[string]any{"ZID": zid, "Host": host, "Type": in.Type, "Value": in.Content, "TTL": in.TTL, "Line": line}
	if in.Description != "" {
		input["Remark"] = in.Description
	}
	if in.Weight != nil {
		input["Weight"] = *in.Weight
	}
	var data record
	if err := p.call(ctx, "CreateRecord", nil, input, &data); err != nil {
		return "", err
	}
	if data.RecordID == "" {
		return "", errResponse
	}
	return data.RecordID, nil
}

// UpdateRecord and DeleteRecord accept an account-wide ID. Only use IDs
// returned within the selected ZID, including when parent and child zones coexist.
func (p *provider) record(ctx context.Context, zone, id string) (*record, error) {
	if id == "" {
		return nil, dns.ErrInvalidDNSRequest
	}
	_, zid, err := p.zone(ctx, zone)
	if err != nil {
		return nil, err
	}
	for page := 1; ; page++ {
		data, err := p.records(ctx, zid, page, "")
		if err != nil {
			return nil, err
		}
		for i := range data.Records {
			if data.Records[i].RecordID == id {
				if slices.Contains(data.Records[i].Tags, "GTMLock") {
					return nil, dns.ErrInvalidDNSRequest
				}
				data.Records[i].zoneID = zid
				return &data.Records[i], nil
			}
		}
		if len(data.Records) == 0 || page*dns.DNSPageSize >= *data.TotalCount {
			return nil, domain.ErrRecordNotFound
		}
	}
}

// TTL is shared by records with the same owner, type and line. A per-value
// edit may change it only if no other record in the set would be affected.
func (p *provider) guardSiblings(ctx context.Context, zid int64, id, host, typ, line string, ttl int) error {
	if typ != "A" && typ != "AAAA" && typ != "CNAME" {
		return nil
	}
	for page := 1; dnsutil.ValidPage(page); page++ {
		data, err := p.records(ctx, zid, page, host)
		if err != nil {
			return err
		}
		for _, r := range data.Records {
			if r.RecordID != id && strings.EqualFold(r.Host, host) && r.Type == typ && r.Line == line && r.TTL != ttl {
				return dns.ErrInvalidDNSRequest
			}
		}
		if page*dns.DNSPageSize >= *data.TotalCount {
			return nil
		}
	}
	return errResponse
}
func (p *provider) update(ctx context.Context, r *record) error {
	input := map[string]any{"RecordID": r.RecordID, "Host": r.Host, "Type": r.Type, "Value": r.Value, "TTL": r.TTL, "Line": r.Line, "Remark": r.Remark}
	if r.Weight != nil {
		input["Weight"] = *r.Weight
	}
	var data record
	if err := p.call(ctx, "UpdateRecord", nil, input, &data); err != nil {
		return err
	}
	if data.RecordID != r.RecordID {
		return errResponse
	}
	return nil
}
func (p *provider) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	r, err := p.record(ctx, zone, id)
	if err != nil {
		return "", err
	}
	if in.TTL < 1 || in.Content == "" {
		return "", dns.ErrInvalidDNSRequest
	}
	if in.TTL != r.TTL {
		if err := p.guardSiblings(ctx, r.zoneID, id, r.Host, r.Type, r.Line, in.TTL); err != nil {
			return "", err
		}
	}
	r.Value, err = dnsutil.MXValue(r.Type, in.Content, nil, r.Value)
	if err != nil {
		return "", err
	}
	r.TTL = in.TTL
	if err := p.update(ctx, r); err != nil {
		return "", err
	}
	return id, nil
}
func (p *provider) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	if _, err := p.record(ctx, zone, id); err != nil {
		return "", err
	}
	if err := p.call(ctx, "DeleteRecord", nil, map[string]any{"RecordID": id}, nil); err != nil {
		return "", err
	}
	return id, nil
}

func (p *provider) SetDNSRecordStatus(ctx context.Context, zone, id string, on bool) (string, error) {
	if _, err := p.record(ctx, zone, id); err != nil {
		return "", err
	}
	var out record
	if err := p.call(ctx, "UpdateRecordStatus", nil, map[string]any{"RecordID": id, "Enable": on}, &out); err != nil {
		return "", err
	}
	if out.RecordID != id || out.Enable == nil || *out.Enable != on {
		return "", errResponse
	}
	return id, nil
}
func (p *provider) CreateZone(ctx context.Context, raw string) (*dns.Zone, error) {
	name, err := dnsutil.ZoneName(raw)
	if err != nil {
		return nil, err
	}
	var out zoneInfo
	if err := p.call(ctx, "CreateZone", nil, map[string]any{"ZoneName": name}, &out); err != nil {
		return nil, err
	}
	if out.ZID < 1 || !strings.EqualFold(out.ZoneName, name) {
		return nil, errResponse
	}
	return &dns.Zone{ID: name, Name: name, Status: out.Stage.String()}, nil
}

func (p *provider) ZoneDetails(ctx context.Context, zone string) (*dns.ZoneDetails, error) {
	name, zid, err := p.zone(ctx, zone)
	if err != nil {
		return nil, err
	}
	q := url.Values{"ZID": {strconv.FormatInt(zid, 10)}}
	var info struct {
		ZoneName, TradeCode   string
		Stage                 json.Number
		AllocateDNSServerList []string
	}
	if err := p.call(ctx, "QueryZone", q, nil, &info); err != nil {
		return nil, err
	}
	if !strings.EqualFold(info.ZoneName, name) {
		return nil, errResponse
	}
	// QueryZone returns the edition. ListLines with ZID returns the routes
	// enabled for that specific edition.
	minTTL := map[string]int{"free_inner": 600, "professional_inner": 300, "enterprise_inner": 60, "ultimate_inner": 1, "ultimate_exclusive_inner": 1}
	details := &dns.ZoneDetails{Name: name, Status: info.Stage.String(), Plan: info.TradeCode, MinTTL: minTTL[info.TradeCode], Nameservers: info.AllocateDNSServerList, Lines: []dns.RecordLine{{ID: "default", Name: "Default"}}}
	seen := map[string]bool{"default": true}
	for _, action := range []string{"ListLines", "ListCustomLines"} {
		if action == "ListCustomLines" {
			q.Del("ZID")
		}
		for page := 1; ; page++ {
			q.Set("PageNumber", strconv.Itoa(page))
			q.Set("PageSize", strconv.Itoa(dns.DNSPageSize))
			var out struct {
				TotalCount *int
				Lines      []struct {
					Value, Name, FatherValue string
				}
				CustomerLines []struct{ Line, NameCN string }
			}
			if err := p.call(ctx, action, q, nil, &out); err != nil {
				return nil, err
			}
			count := len(out.Lines) + len(out.CustomerLines)
			if out.TotalCount == nil || count != min(dns.DNSPageSize, max(0, *out.TotalCount-(page-1)*dns.DNSPageSize)) {
				return nil, errResponse
			}
			for _, line := range out.Lines {
				if seen[line.Value] {
					continue
				}
				seen[line.Value] = true
				details.Lines = append(details.Lines, dns.RecordLine{ID: line.Value, Name: line.Name, Parent: line.FatherValue})
			}
			for _, line := range out.CustomerLines {
				if line.Line == "" || seen[line.Line] {
					return nil, errResponse
				}
				seen[line.Line] = true
				details.Lines = append(details.Lines, dns.RecordLine{ID: line.Line, Name: line.NameCN})
			}
			if page*dns.DNSPageSize >= *out.TotalCount {
				break
			}
		}
	}
	return details, nil
}

func (p *provider) BatchFields() []string { return []string{"status", "remark", "line", "weight"} }
func (p *provider) BatchAttribute(ctx context.Context, zone, id, field string) (string, error) {
	r, err := p.record(ctx, zone, id)
	if err != nil {
		return "", err
	}
	switch field {
	case "remark":
		return r.Remark, nil
	case "line":
		return r.Line, nil
	case "weight":
		if r.Weight != nil {
			return strconv.Itoa(*r.Weight), nil
		}
		return "", nil
	case "status":
		if *r.Enable {
			return "enabled", nil
		}
		return "disabled", nil
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
	r, err := p.record(ctx, zone, id)
	if err != nil {
		return err
	}
	switch field {
	case "remark":
		r.Remark = value
	case "line":
		if value == "" {
			return dns.ErrInvalidDNSRequest
		}
		if err := p.guardSiblings(ctx, r.zoneID, id, r.Host, r.Type, value, r.TTL); err != nil {
			return err
		}
		r.Line = value
	case "weight":
		n, e := strconv.Atoi(value)
		if e != nil || n < 0 {
			return dns.ErrInvalidDNSRequest
		}
		r.Weight = &n
	default:
		return dns.ErrInvalidDNSRequest
	}
	return p.update(ctx, r)
}
