// Package jdcloud manages JD Cloud DNS v2 resource records.
package jdcloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	sdk "github.com/jdcloud-api/jdcloud-sdk-go/core"
	api "github.com/jdcloud-api/jdcloud-sdk-go/services/domainservice/apis"
	model "github.com/jdcloud-api/jdcloud-sdk-go/services/domainservice/models"
)

const region = "cn-north-1"

var errResponse = errors.New("invalid JD Cloud DNS response")

type provider struct {
	signer   *sdk.Signer
	endpoint string
	client   *http.Client
}

func New(a *domain.Access) (dns.Provider, error) {
	id, secret := dnsutil.Field(a, "accessKeyId"), dnsutil.Field(a, "accessKeySecret")
	if id == "" || secret == "" {
		return nil, domain.ErrInvalidParams
	}
	signer := sdk.NewSigner(*sdk.NewCredentials(id, secret), sdk.NewDummyLogger())
	return &provider{signer, "https://domainservice.jdcloud-api.com/v2/regions/" + region + "/domain", dnsutil.HTTPClientFor(a)}, nil
}
func (p *provider) call(ctx context.Context, method, path string, q url.Values, input, dest any) error {
	var payload []byte
	if input != nil {
		var err error
		payload, err = json.Marshal(input)
		if err != nil {
			return dns.ErrInvalidDNSRequest
		}
	}
	u := p.endpoint + path
	if len(q) > 0 {
		u += "?" + strings.ReplaceAll(q.Encode(), "+", "%20")
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(payload))
	if err != nil {
		return dns.ErrInvalidDNSRequest
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-jdcloud-algorithm", "JDCLOUD2-HMAC-SHA256")
	if _, err := p.signer.Sign(req, bytes.NewReader(payload), "domainservice", region, time.Now()); err != nil {
		return errors.New("JD Cloud DNS signing failed")
	}
	body, err := dnsutil.ReadResponse(p.client, req)
	if err != nil {
		return err
	}
	var env struct {
		Error     *struct{ Code int }
		Result    json.RawMessage
		RequestID string
	}
	if json.Unmarshal(body, &env) != nil || env.Error != nil && env.Error.Code != 0 {
		return errResponse
	}
	if dest == nil {
		if env.RequestID == "" && len(env.Result) == 0 {
			return errResponse
		}
		return nil
	}
	if len(env.Result) == 0 || string(env.Result) == "null" || json.Unmarshal(env.Result, dest) != nil {
		return errResponse
	}
	return nil
}
func paging(page int) url.Values {
	return url.Values{"pageNumber": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(dns.DNSPageSize)}}
}

type domainPage struct {
	TotalCount *int `json:"totalCount"`
	DataList   []struct {
		model.DomainInfo
		Status json.RawMessage `json:"resolvingStatus"`
	} `json:"dataList"`
}

func (p *provider) domains(ctx context.Context, page int, q url.Values) (*domainPage, error) {
	var data domainPage
	if err := p.call(ctx, http.MethodGet, "", q, nil, &data); err != nil {
		return nil, err
	}
	if data.TotalCount == nil || *data.TotalCount < 0 || len(data.DataList) != min(dns.DNSPageSize, max(0, *data.TotalCount-(page-1)*dns.DNSPageSize)) {
		return nil, errResponse
	}
	for i := range data.DataList {
		r := &data.DataList[i]
		if len(r.Status) > 0 {
			if r.Status[0] == '"' {
				if json.Unmarshal(r.Status, &r.ResolvingStatus) != nil {
					return nil, errResponse
				}
			} else {
				var status json.Number
				if json.Unmarshal(r.Status, &status) != nil {
					return nil, errResponse
				}
				r.ResolvingStatus = status.String()
			}
		}
	}
	return &data, nil
}
func (p *provider) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	data, err := p.domains(ctx, page, paging(page))
	if err != nil {
		return nil, err
	}
	out := dnsutil.Page[dns.Zone](page, *data.TotalCount)
	for _, r := range data.DataList {
		z, err := dnsutil.ZoneName(r.DomainName)
		if err != nil || r.Id < 1 {
			return nil, errResponse
		}
		out.Items = append(out.Items, dns.Zone{ID: strconv.Itoa(r.Id), Name: z, Status: r.ResolvingStatus})
	}
	return out, nil
}
func (p *provider) zone(ctx context.Context, id string) (*model.DomainInfo, error) {
	if _, err := dnsutil.PositiveID(id); err != nil {
		return nil, err
	}
	q := paging(1)
	q.Set("domainId", id)
	data, err := p.domains(ctx, 1, q)
	if err != nil {
		return nil, err
	}
	for _, r := range data.DataList {
		if strconv.Itoa(r.Id) == id {
			name, err := dnsutil.ZoneName(r.DomainName)
			if err != nil {
				return nil, errResponse
			}
			r.DomainName = name
			return &r.DomainInfo, nil
		}
	}
	return nil, domain.ErrRecordNotFound
}
func recordsPath(zone string) string { return "/" + zone + "/ResourceRecord" }

type wireRecord struct {
	NativeWeight    *int  `json:"weight"`
	IsCloudResource *bool `json:"jcloudRes"`
	Preference      *int  `json:"mxPriority"`
	SrvPort         *int  `json:"port"`
	model.RRInfo
	// Some versions return numeric statuses, others return a quoted number.
	Status json.Number `json:"resolvingStatus"`
}
type recordPage struct {
	TotalCount *int         `json:"totalCount"`
	DataList   []wireRecord `json:"dataList"`
}

func (p *provider) records(ctx context.Context, zone string, page int, filter string) (*recordPage, error) {
	q := paging(page)
	if filter != "" {
		q.Set("search", filter)
	}
	var data recordPage
	if err := p.call(ctx, http.MethodGet, recordsPath(zone), q, nil, &data); err != nil {
		return nil, err
	}
	if data.TotalCount == nil || *data.TotalCount < 0 || len(data.DataList) != min(dns.DNSPageSize, max(0, *data.TotalCount-(page-1)*dns.DNSPageSize)) {
		return nil, errResponse
	}
	for i := range data.DataList {
		r := &data.DataList[i]
		if r.NativeWeight != nil {
			r.Weight = *r.NativeWeight
		}
		if r.Preference != nil {
			r.MxPriority = *r.Preference
		}
		if r.SrvPort != nil {
			r.Port = *r.SrvPort
		}
		if r.Type == "MX" && r.Preference == nil || r.Type == "SRV" && (r.Preference == nil || r.SrvPort == nil || r.NativeWeight == nil) {
			return nil, errResponse
		}
		if r.Id < 1 || r.Type == "" || r.HostRecord == "" || r.HostValue == "" || r.Ttl < 1 || len(r.ViewValue) == 0 {
			return nil, errResponse
		}
	}
	return &data, nil
}
func recordContent(r model.RRInfo) string {
	switch r.Type {
	case "SRV":
		return strconv.Itoa(r.MxPriority) + " " + strconv.Itoa(r.Weight) + " " + strconv.Itoa(r.Port) + " " + r.HostValue
	case "MX":
		return strconv.Itoa(r.MxPriority) + " " + r.HostValue
	default:
		return r.HostValue
	}
}
func (p *provider) DNSRecords(ctx context.Context, zone string, page int, filter string) (*dns.DNSPage[dns.DNSRecord], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	z, err := p.zone(ctx, zone)
	if err != nil {
		return nil, err
	}
	if label, err := dnsutil.RelativeName(filter, z.DomainName); err == nil {
		filter = label
	}
	data, err := p.records(ctx, zone, page, filter)
	if err != nil {
		return nil, err
	}
	out := dnsutil.Page[dns.DNSRecord](page, *data.TotalCount)
	for _, r := range data.DataList {
		out.Items = append(out.Items, r.row(z.DomainName))
	}
	return out, nil
}
func parseContent(typ, value string) (string, *int, *int, *int, error) {
	if typ != "MX" && typ != "SRV" {
		return value, nil, nil, nil, nil
	}
	fields := strings.Fields(value)
	n := 1
	if typ == "SRV" {
		n = 3
	}
	if len(fields) != n+1 {
		return "", nil, nil, nil, dns.ErrInvalidDNSRequest
	}
	var params [3]*int
	for i := 0; i < n; i++ {
		v, err := strconv.ParseUint(fields[i], 10, 16)
		if err != nil {
			return "", nil, nil, nil, dns.ErrInvalidDNSRequest
		}
		k := int(v)
		params[i] = &k
	}
	return fields[n], params[0], params[1], params[2], nil
}
func (p *provider) CreateDNSRecord(ctx context.Context, zone string, in dns.RecordInput) (string, error) {
	z, err := p.zone(ctx, zone)
	if err != nil {
		return "", err
	}
	host, err := dnsutil.RelativeName(in.Name, z.DomainName)
	if err != nil {
		return "", err
	}
	line := -1
	if in.Line != "" {
		line, err = strconv.Atoi(in.Line)
		if err != nil || line < -1 {
			return "", dns.ErrInvalidDNSRequest
		}
	}
	if in.TTL < 1 || in.Type == "" || in.Content == "" || in.Description != "" {
		return "", dns.ErrInvalidDNSRequest
	}
	in.Content, err = dnsutil.MXValue(in.Type, in.Content, in.Priority, "")
	if err != nil {
		return "", err
	}
	value, priority, weight, port, err := parseContent(in.Type, in.Content)
	if err != nil {
		return "", err
	}
	if in.Weight != nil {
		if weight != nil || *in.Weight < 0 || *in.Weight > 100 {
			return "", dns.ErrInvalidDNSRequest
		}
		weight = in.Weight
	}
	switch in.Type {
	case "REDIRECT_URL":
		in.Type = "EXPLICIT_URL"
	case "FORWARD_URL":
		in.Type = "IMPLICIT_URL"
	}
	req := model.AddRR{HostRecord: host, HostValue: value, Ttl: in.TTL, Type: in.Type, ViewValue: line, MxPriority: priority, Weight: weight, Port: port}
	var data api.CreateResourceRecordResult
	if err := p.call(ctx, http.MethodPost, recordsPath(zone), nil, map[string]any{"req": &req}, &data); err != nil {
		return "", err
	}
	if data.DataList.Id < 1 {
		return "", errResponse
	}
	return strconv.Itoa(data.DataList.Id), nil
}
func (p *provider) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	if in.TTL < 1 || in.Content == "" {
		return "", dns.ErrInvalidDNSRequest
	}
	z, r, err := p.current(ctx, zone, id)
	if err != nil {
		return "", err
	}
	content, err := dnsutil.MXValue(r.Type, in.Content, nil, recordContent(r.RRInfo))
	if err != nil {
		return "", err
	}
	value, priority, weight, port, err := parseContent(r.Type, content)
	if err != nil {
		return "", err
	}
	switch r.Type {
	case "A", "AAAA", "CNAME", "JNAME":
		weight = r.NativeWeight
	}
	return p.update(ctx, zone, id, z, r, value, in.TTL, priority, weight, port)
}
func (p *provider) update(ctx context.Context, zone, id string, z *model.DomainInfo, r *wireRecord, value string, ttl int, priority, weight, port *int) (string, error) {
	req := map[string]any{"domainName": z.DomainName, "hostRecord": r.HostRecord, "hostValue": value, "ttl": ttl, "type": r.Type, "viewValue": r.ViewValue[len(r.ViewValue)-1]}
	if r.IsCloudResource != nil {
		req["jcloudRes"] = *r.IsCloudResource
	}
	if priority != nil {
		req["mxPriority"] = *priority
	}
	if port != nil {
		req["port"] = *port
	}
	if weight != nil {
		req["weight"] = *weight
	}
	if err := p.call(ctx, http.MethodPut, recordsPath(zone)+"/"+id, nil, map[string]any{"req": &req}, nil); err != nil {
		return "", err
	}
	return id, nil
}
func (p *provider) current(ctx context.Context, zone, id string) (*model.DomainInfo, *wireRecord, error) {
	if _, err := dnsutil.PositiveID(id); err != nil {
		return nil, nil, err
	}
	z, err := p.zone(ctx, zone)
	if err != nil {
		return nil, nil, err
	}
	for page := 1; dnsutil.ValidPage(page); page++ {
		data, err := p.records(ctx, zone, page, "")
		if err != nil {
			return nil, nil, err
		}
		for i := range data.DataList {
			if strconv.Itoa(data.DataList[i].Id) == id {
				return z, &data.DataList[i], nil
			}
		}
		if page*dns.DNSPageSize >= *data.TotalCount {
			break
		}
	}
	return nil, nil, domain.ErrRecordNotFound
}
func (p *provider) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	if _, _, err := p.current(ctx, zone, id); err != nil {
		return "", err
	}
	if err := p.call(ctx, http.MethodDelete, recordsPath(zone)+"/"+id, nil, nil, nil); err != nil {
		return "", err
	}
	return id, nil
}

func recordStatus(value string) string {
	switch value {
	case "2":
		return "enabled"
	case "4":
		return "disabled"
	default:
		return value
	}
}
func (p *provider) SetDNSRecordStatus(ctx context.Context, zone, id string, on bool) (string, error) {
	if _, _, err := p.current(ctx, zone, id); err != nil {
		return "", err
	}
	action := "disable"
	if on {
		action = "enable"
	}
	if err := p.call(ctx, http.MethodPut, recordsPath(zone)+"/"+id+"/status", nil, map[string]string{"action": action}, nil); err != nil {
		return "", err
	}
	return id, nil
}
func (p *provider) ZoneDetails(ctx context.Context, id string) (*dns.ZoneDetails, error) {
	z, err := p.zone(ctx, id)
	if err != nil {
		return nil, err
	}
	var lines api.DescribeViewTreeResult
	q := url.Values{"packId": {strconv.Itoa(z.PackId)}, "viewId": {"0"}}
	if err := p.call(ctx, http.MethodGet, "/"+id+"/viewTree", q, nil, &lines); err != nil {
		return nil, err
	}
	out := &dns.ZoneDetails{Name: z.DomainName, Status: z.ResolvingStatus, Plan: z.PackName, Nameservers: z.DefNsList, Lines: []dns.RecordLine{}}
	var flatten func([]model.ViewTree, string)
	flatten = func(entries []model.ViewTree, parent string) {
		for _, r := range entries {
			if r.Disabled {
				continue
			}
			key := strconv.Itoa(r.Value)
			out.Lines = append(out.Lines, dns.RecordLine{ID: key, Name: r.Label, Parent: parent})
			flatten(r.Children, key)
		}
	}
	flatten(lines.Data, "")
	return out, nil
}
func (p *provider) CreateZone(ctx context.Context, raw string) (*dns.Zone, error) {
	name, err := dnsutil.ZoneName(raw)
	if err != nil {
		return nil, err
	}
	var result api.CreateDomainResult
	if err := p.call(ctx, http.MethodPost, "", nil, map[string]any{"packId": 0, "domainName": name}, &result); err != nil {
		return nil, err
	}
	if result.Data.Id < 1 || !strings.EqualFold(result.Data.DomainName, name) {
		return nil, errResponse
	}
	return &dns.Zone{ID: strconv.Itoa(result.Data.Id), Name: name}, nil
}

func (p *provider) BatchFields() []string { return []string{"status", "line", "weight"} }
func (p *provider) BatchAttribute(ctx context.Context, zone, id, field string) (string, error) {
	_, r, err := p.current(ctx, zone, id)
	if err != nil {
		return "", err
	}
	switch field {
	case "line":
		return strconv.Itoa(r.ViewValue[len(r.ViewValue)-1]), nil
	case "weight":
		weight := r.routingWeight()
		if weight == nil {
			return "", nil
		}
		return strconv.Itoa(*weight), nil
	case "status":
		s := recordStatus(r.Status.String())
		if s == "enabled" || s == "disabled" {
			return s, nil
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
	z, r, err := p.current(ctx, zone, id)
	if err != nil {
		return err
	}
	host, priority, weight, port, err := parseContent(r.Type, recordContent(r.RRInfo))
	if err != nil {
		return err
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return dns.ErrInvalidDNSRequest
	}
	switch field {
	case "line":
		if n < -1 {
			return dns.ErrInvalidDNSRequest
		}
		r.ViewValue = []int{n}
	case "weight":
		if n < 0 || n > 100 || (r.Type != "A" && r.Type != "AAAA" && r.Type != "CNAME" && r.Type != "JNAME") {
			return dns.ErrInvalidDNSRequest
		}
		r.NativeWeight = &n
	default:
		return dns.ErrInvalidDNSRequest
	}
	switch r.Type {
	case "A", "AAAA", "CNAME", "JNAME":
		weight = r.NativeWeight
	}
	_, err = p.update(ctx, zone, id, z, r, host, r.Ttl, priority, weight, port)
	return err
}

func (r wireRecord) routingWeight() *int {
	switch r.Type {
	case "A", "AAAA", "CNAME", "JNAME":
		return r.NativeWeight
	default:
		return nil
	}
}

func (r wireRecord) row(zone string) dns.DNSRecord {
	return dns.DNSRecord{Priority: r.Preference, ID: strconv.Itoa(r.Id), Name: dnsutil.FullName(r.HostRecord, zone), Type: r.Type, TTL: r.Ttl, Line: strconv.Itoa(r.ViewValue[len(r.ViewValue)-1]), Weight: r.routingWeight(), Content: recordContent(r.RRInfo), Status: recordStatus(r.Status.String())}
}
