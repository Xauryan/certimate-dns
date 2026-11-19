// Package bt manages DNS records on the Baota domain management platform.
package bt

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	u "github.com/certimate-go/certimate/internal/dnsdrivers/selfhostutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

const endpoint = "https://dmp.bt.cn/api/v1/dns"

var errResponse = errors.New("invalid Baota DNS response")
var errCreated = errors.New("Baota DNS accepted the create request but the new record ID could not be confirmed; refresh the zone before retrying")

type provider struct {
	accountID, accessKey, secretKey string
	http                            *http.Client
}

func New(a *domain.Access) (dns.Provider, error) {
	p := &provider{accountID: dnsutil.Field(a, "accountId"), accessKey: dnsutil.Field(a, "accessKey"), secretKey: dnsutil.Field(a, "secretKey"), http: dnsutil.HTTPClientFor(a)}
	if p.accountID == "" || p.accessKey == "" || p.secretKey == "" {
		return nil, domain.ErrInvalidParams
	}
	return p, nil
}

func (p *provider) post(ctx context.Context, route string, params map[string]any, result any) error {
	data, err := json.Marshal(params)
	if err != nil {
		return dns.ErrInvalidDNSRequest
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+route, bytes.NewReader(data))
	if err != nil {
		return dns.ErrInvalidDNSRequest
	}
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(p.secretKey))
	mac.Write([]byte(strings.Join([]string{p.accountID, stamp, req.Method, req.URL.Path, ""}, "\n")))
	mac.Write(data)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Account-ID", p.accountID)
	req.Header.Set("X-Access-Key", p.accessKey)
	req.Header.Set("X-Timestamp", stamp)
	req.Header.Set("X-Signature", hex.EncodeToString(mac.Sum(nil)))
	raw, err := dnsutil.ReadResponse(p.http, req)
	if err != nil {
		return err
	}
	var envelope struct {
		Code   *int            `json:"code"`
		Status *bool           `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Code == nil {
		return errResponse
	}
	if *envelope.Code == 404 {
		return domain.ErrRecordNotFound
	}
	if *envelope.Code != 0 || envelope.Status != nil && !*envelope.Status {
		return errors.New("Baota DNS rejected the request")
	}
	if result != nil && (len(envelope.Data) == 0 || string(envelope.Data) == "null" || json.Unmarshal(envelope.Data, result) != nil) {
		return errResponse
	}
	return nil
}

type zoneKey struct {
	ID   int64 `json:"domain_id"`
	Type int   `json:"domain_type"`
}

func (z zoneKey) params() map[string]any {
	return map[string]any{"domain_id": z.ID, "domain_type": z.Type}
}
func (z zoneKey) String() string {
	return strconv.FormatInt(z.ID, 10) + "|" + strconv.Itoa(z.Type)
}
func parseZone(id string) (zoneKey, error) {
	n, t, ok := strings.Cut(id, "|")
	i, err := dnsutil.PositiveID(n)
	if !ok || err != nil || (t != "1" && t != "2") {
		return zoneKey{}, dns.ErrInvalidDNSRequest
	}
	typ, _ := strconv.Atoi(t)
	return zoneKey{i, typ}, nil
}

func (p *provider) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	var result struct {
		Total *int `json:"total"`
		Data  []struct {
			LocalID    int64  `json:"local_id"`
			DomainType int    `json:"domain_type"`
			Name       string `json:"full_domain"`
			NSStatus   int    `json:"ns_status"`
		} `json:"data"`
	}
	if err := p.post(ctx, "/manage/list_domains", map[string]any{"p": page, "rows": dns.DNSPageSize}, &result); err != nil {
		return nil, err
	}
	if result.Total == nil || !u.CompletePage(page, *result.Total, len(result.Data)) || result.Data == nil {
		return nil, errResponse
	}
	out := dnsutil.Page[dns.Zone](page, *result.Total)
	for _, row := range result.Data {
		key := zoneKey{row.LocalID, row.DomainType}
		name, err := dnsutil.ZoneName(row.Name)
		if err != nil || key.ID <= 0 || (key.Type != 1 && key.Type != 2) {
			return nil, errResponse
		}
		status := "pending"
		if row.NSStatus == 1 {
			status = "active"
		}
		if row.NSStatus == 2 {
			status = "inactive"
		}
		out.Items = append(out.Items, dns.Zone{ID: key.String(), Name: name, Status: status})
	}
	return out, nil
}

func (p *provider) zoneName(ctx context.Context, key zoneKey) (string, error) {
	var data struct {
		zoneKey
		Name string `json:"full_domain"`
	}
	if err := p.post(ctx, "/manage/check_domain_status", key.params(), &data); err != nil {
		return "", err
	}
	if data.zoneKey != key {
		return "", domain.ErrRecordNotFound
	}
	name, err := dnsutil.ZoneName(data.Name)
	if err != nil {
		return "", errResponse
	}
	return name, nil
}

type record struct {
	zoneKey
	ID     int64  `json:"record_id"`
	Host   string `json:"record"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	TTL    int    `json:"TTL"`
	ViewID int64  `json:"viewID"`
	State  int    `json:"state"`
	MX     int    `json:"MX"`
	Remark string `json:"remark"`
}
type recordPage struct {
	Count *int     `json:"count"`
	Data  []record `json:"data"`
}

func (p *provider) records(ctx context.Context, key zoneKey, page int, filter string) (*recordPage, error) {
	params := key.params()
	params["p"], params["rows"] = page, dns.DNSPageSize
	if filter != "" {
		params["searchKey"], params["searchValue"] = "record", filter
	}
	var result recordPage
	if err := p.post(ctx, "/record/list", params, &result); err != nil {
		return nil, err
	}
	if result.Count == nil || !u.CompletePage(page, *result.Count, len(result.Data)) || result.Data == nil {
		return nil, errResponse
	}
	for _, r := range result.Data {
		if r.zoneKey != key || r.ID <= 0 || r.Host == "" || r.Type == "" || r.TTL <= 0 {
			return nil, errResponse
		}
	}
	return &result, nil
}
func (p *provider) DNSRecords(ctx context.Context, zone string, page int, filter string) (*dns.DNSPage[dns.DNSRecord], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	key, err := parseZone(zone)
	if err != nil {
		return nil, err
	}
	name, err := p.zoneName(ctx, key)
	if err != nil {
		return nil, err
	}
	if host, e := dnsutil.RelativeName(filter, name); e == nil {
		filter = host
	}
	result, err := p.records(ctx, key, page, filter)
	if err != nil {
		return nil, err
	}
	out := dnsutil.Page[dns.DNSRecord](page, *result.Count)
	for _, r := range result.Data {
		status := "enabled"
		if r.State == 1 {
			status = "disabled"
		}
		out.Items = append(out.Items, dns.DNSRecord{ID: strconv.FormatInt(r.ID, 10), Type: r.Type, Name: dnsutil.FullName(r.Host, name), Content: r.Value, TTL: r.TTL, Line: strconv.FormatInt(r.ViewID, 10), Status: status, Description: r.Remark, Weight: &r.MX, Priority: &r.MX})
	}
	return out, nil
}

func (p *provider) walkRecords(ctx context.Context, key zoneKey, filter string, visit func(record) bool) error {
	total := -1
	seen := map[int64]bool{}
	for page := 1; dnsutil.ValidPage(page); page++ {
		result, err := p.records(ctx, key, page, filter)
		if err != nil {
			return err
		}
		if total != -1 && total != *result.Count {
			return errResponse
		}
		total = *result.Count
		for _, r := range result.Data {
			if seen[r.ID] {
				return errResponse
			}
			seen[r.ID] = true
			if !visit(r) {
				return nil
			}
		}
		if page*dns.DNSPageSize >= *result.Count {
			return nil
		}
		if len(result.Data) != dns.DNSPageSize {
			return errResponse
		}
	}
	return errResponse
}

func (p *provider) CreateDNSRecord(ctx context.Context, zone string, in dns.RecordInput) (string, error) {
	key, err := parseZone(zone)
	if err != nil {
		return "", err
	}
	view := int64(0)
	if in.Line != "" && in.Line != "default" {
		view, err = strconv.ParseInt(in.Line, 10, 64)
		if err != nil || view < 0 {
			return "", dns.ErrInvalidDNSRequest
		}
	}
	if in.TTL < 300 || in.Content == "" || in.Type == "" {
		return "", dns.ErrInvalidDNSRequest
	}
	name, err := p.zoneName(ctx, key)
	if err != nil {
		return "", err
	}
	host, err := dnsutil.RelativeName(in.Name, name)
	if err != nil {
		return "", err
	}

	// The documented create response is empty. Track prior IDs so that an
	// existing matching value can never be claimed by a new challenge.
	defer u.LockZone(endpoint, zone)()
	prior := map[int64]bool{}
	err = p.walkRecords(ctx, key, host, func(row record) bool { prior[row.ID] = true; return true })
	if err != nil {
		return "", err
	}
	params := key.params()
	params["record"], params["type"], params["value"], params["ttl"] = host, in.Type, in.Content, in.TTL
	params["view_id"], params["mx"] = view, 1
	if in.Weight != nil {
		params["mx"] = *in.Weight
	}
	if in.Type == "MX" && in.Priority != nil {
		params["mx"] = *in.Priority
	}
	if in.Description != "" {
		params["remark"] = in.Description
	}
	var created struct {
		ID int64 `json:"record_id"`
	}
	if err = p.post(ctx, "/record/create", params, &created); err != nil {
		return "", err
	}
	if created.ID > 0 && !prior[created.ID] {
		return strconv.FormatInt(created.ID, 10), nil
	}
	var id int64
	err = p.walkRecords(ctx, key, host, func(row record) bool {
		if prior[row.ID] || !strings.EqualFold(host, row.Host) || row.Type != in.Type || row.Value != in.Content || row.ViewID != view || row.TTL != in.TTL {
			return true
		}
		if id != 0 {
			id = 0
			return false
		}
		id = row.ID
		return true
	})
	if err != nil || id == 0 {
		return "", errCreated
	}
	return strconv.FormatInt(id, 10), nil
}

func (p *provider) old(ctx context.Context, zone, id string) (record, error) {
	key, err := parseZone(zone)
	if err != nil {
		return record{}, err
	}
	number, err := dnsutil.PositiveID(id)
	if err != nil {
		return record{}, err
	}
	var found record
	err = p.walkRecords(ctx, key, "", func(r record) bool {
		if r.ID == number {
			found = r
		}
		return true
	})
	if err != nil {
		return record{}, err
	}
	if found.ID == 0 {
		return record{}, domain.ErrRecordNotFound
	}
	return found, nil
}
func (p *provider) change(ctx context.Context, zone, id, route string, fields map[string]any) (string, error) {
	r, err := p.old(ctx, zone, id)
	if err != nil {
		return "", err
	}
	params := r.zoneKey.params()
	params["record_id"] = r.ID
	for k, v := range fields {
		params[k] = v
	}
	if err = p.post(ctx, route, params, nil); err != nil {
		return "", err
	}
	return id, nil
}
func (p *provider) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	if in.TTL < 300 || in.Content == "" {
		return "", dns.ErrInvalidDNSRequest
	}
	return p.change(ctx, zone, id, "/record/update", map[string]any{"value": in.Content, "ttl": in.TTL})
}
func (p *provider) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	return p.change(ctx, zone, id, "/record/delete", nil)
}

func (p *provider) CreateZone(ctx context.Context, name string) (*dns.Zone, error) {
	name, err := dnsutil.ZoneName(name)
	if err != nil {
		return nil, err
	}
	var r struct {
		ID   int64  `json:"domain_id"`
		Name string `json:"full_domain"`
	}
	if err = p.post(ctx, "/manage/add_external_domain", map[string]any{"full_domain": name}, &r); err != nil {
		return nil, err
	}
	if r.ID <= 0 || !strings.EqualFold(name, r.Name) {
		return nil, errResponse
	}
	return &dns.Zone{ID: (zoneKey{r.ID, 2}).String(), Name: name, Status: "pending"}, nil
}

type view struct {
	ID       int64 `json:"viewId"`
	Name     string
	Free     bool
	Children []view
}

func (p *provider) ZoneDetails(ctx context.Context, id string) (*dns.ZoneDetails, error) {
	key, err := parseZone(id)
	if err != nil {
		return nil, err
	}
	name, err := p.zoneName(ctx, key)
	if err != nil {
		return nil, err
	}
	var views []view
	if err = p.post(ctx, "/record/get_views", map[string]any{}, &views); err != nil {
		return nil, err
	}
	out := &dns.ZoneDetails{Name: name, MinTTL: 300, Lines: []dns.RecordLine{}}
	var collect func([]view, string)
	seen := map[string]bool{}
	collect = func(views []view, parent string) {
		for _, v := range views {
			id := strconv.FormatInt(v.ID, 10)
			if !v.Free || seen[id] {
				continue
			}
			seen[id] = true
			out.Lines = append(out.Lines, dns.RecordLine{ID: id, Name: v.Name, Parent: parent})
			collect(v.Children, id)
		}
	}
	collect(views, "")
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
		if r.State == 1 {
			return "disabled", nil
		}
		return "enabled", nil
	case "remark":
		return r.Remark, nil
	case "weight":
		return strconv.Itoa(r.MX), nil
	case "line":
		return strconv.FormatInt(r.ViewID, 10), nil
	}
	return "", dns.ErrInvalidDNSRequest
}
func (p *provider) SetBatchAttribute(ctx context.Context, zone, id, field, value string) error {
	route := "/record/update"
	fields := map[string]any{}
	switch field {
	case "status":
		switch value {
		case "enabled":
			route = "/record/start"
		case "disabled":
			route = "/record/pause"
		default:
			return dns.ErrInvalidDNSRequest
		}
	case "remark":
		fields["remark"] = value
	case "weight", "line":
		n, err := strconv.ParseUint(value, 10, 31)
		if err != nil {
			return dns.ErrInvalidDNSRequest
		}
		if field == "line" {
			fields["view_id"] = n
		} else {
			fields["mx"] = n
		}
	default:
		return dns.ErrInvalidDNSRequest
	}
	_, err := p.change(ctx, zone, id, route, fields)
	return err
}
