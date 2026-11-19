package goedge

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/dnsdrivers/selfhostutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

// GoEdge's update RPC replaces these fields, including type-specific attributes.
type recordData struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Value       string `json:"value"`
	TTL         int    `json:"ttl"`
	Description string `json:"description"`
	Weight      int    `json:"weight"`
	MXPriority  int    `json:"mxPriority"`
	SRVPriority int    `json:"srvPriority"`
	SRVWeight   int    `json:"srvWeight"`
	SRVPort     int    `json:"srvPort"`
	CAAFlag     int    `json:"caaFlag"`
	CAATag      string `json:"caaTag"`
}

type route struct {
	Code, Name, Parent  string
	NSDomain, NSCluster *scopeID
	UserID              json.Number
}
type nsRecord struct {
	recordData
	ID       json.Number
	IsOn     bool
	NSRoutes []route
	NSDomain *scopeID
}

func (r *nsRecord) codes() []string {
	codes := make([]string, 0, len(r.NSRoutes))
	for _, route := range r.NSRoutes {
		if route.Code != "" {
			codes = append(codes, route.Code)
		}
	}
	if len(codes) == 0 {
		return []string{"default"}
	}
	return codes
}

func (r *nsRecord) status() string {
	if r.IsOn {
		return "enabled"
	}
	return "disabled"
}

func (p *provider) list(ctx context.Context, q map[string]any) ([]nsRecord, error) {
	var r struct{ NSRecords []nsRecord }
	err := p.call(ctx, "/NSRecordService/listNSRecords", q, &r)
	return r.NSRecords, err
}

func (p *provider) DNSRecords(ctx context.Context, id string, page int, filter string) (*dns.DNSPage[dns.DNSRecord], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	z, err := p.zone(ctx, id)
	if err != nil {
		return nil, err
	}
	q := map[string]any{"nsDomainId": z.ID}
	if filter != "" {
		if host, err := dnsutil.RelativeName(filter, z.Name); err == nil {
			filter = host
		}
		q["keyword"] = filter
	}
	total, err := p.count(ctx, "/NSRecordService/countAllNSRecords", q)
	if err != nil {
		return nil, err
	}
	q["offset"], q["size"] = (page-1)*dns.DNSPageSize, dns.DNSPageSize
	rows, err := p.list(ctx, q)
	if err != nil {
		return nil, err
	}
	if !selfhostutil.CompletePage(page, total, len(rows)) {
		return nil, selfhostutil.ErrProvider
	}
	result := dnsutil.Page[dns.DNSRecord](page, total)
	for _, r := range rows {
		if _, err := dnsutil.PositiveID(r.ID.String()); err != nil {
			return nil, selfhostutil.ErrProvider
		}
		if r.NSDomain != nil && r.NSDomain.ID != "" && r.NSDomain.ID != z.ID {
			return nil, selfhostutil.ErrProvider
		}
		result.Items = append(result.Items, dns.DNSRecord{ID: r.ID.String(), Type: r.Type, Name: dnsutil.FullName(r.Name, z.Name), Content: r.content(), Weight: &r.Weight, Priority: r.priority(), Description: r.Description, TTL: r.TTL, Line: strings.Join(r.codes(), ","), Status: r.status()})
	}
	return result, nil
}

func (p *provider) record(ctx context.Context, zone, id string) (*nsRecord, error) {
	n, err := dnsutil.PositiveID(id)
	if err != nil {
		return nil, err
	}
	z, err := p.zone(ctx, zone)
	if err != nil {
		return nil, err
	}
	var r struct{ NSRecord *nsRecord }
	if err := p.call(ctx, "/NSRecordService/findNSRecord", map[string]int64{"nsRecordId": n}, &r); err != nil {
		return nil, err
	}
	row := r.NSRecord
	if row == nil || row.ID.String() != id {
		return nil, domain.ErrRecordNotFound
	}
	if row.Type == "" || row.Name == "" || row.TTL <= 0 {
		return nil, selfhostutil.ErrProvider
	}
	if row.NSDomain != nil && row.NSDomain.ID != "" {
		if row.NSDomain.ID != z.ID {
			return nil, domain.ErrRecordNotFound
		}
		return row, nil
	}
	// Older versions omit nsDomain on a record lookup. Confirm the exact ID
	// in the requested zone before using the account-wide update/delete APIs.
	const size = 100
	q := map[string]any{"nsDomainId": z.ID, "keyword": row.Name, "size": size}
	prev := ""
	for offset := 0; ; offset += size {
		q["offset"] = offset
		rows, err := p.list(ctx, q)
		if err != nil {
			return nil, err
		}
		for _, candidate := range rows {
			if candidate.ID == row.ID && (candidate.NSDomain == nil || candidate.NSDomain.ID == "" || candidate.NSDomain.ID == z.ID) {
				return row, nil
			}
		}
		if len(rows) < size {
			return nil, domain.ErrRecordNotFound
		}
		last := rows[len(rows)-1].ID.String()
		if last == prev {
			return nil, selfhostutil.ErrProvider
		}
		prev = last
	}
}

func routeCodes(line string) ([]string, error) {
	if line == "" {
		return []string{"default"}, nil
	}
	var codes []string
	seen := map[string]bool{}
	for _, v := range strings.Split(line, ",") {
		v = strings.TrimSpace(v)
		if v == "" || len(v) > 256 {
			return nil, dns.ErrInvalidDNSRequest
		}
		if !seen[v] {
			codes = append(codes, v)
			seen[v] = true
		}
	}
	return codes, nil
}

func (p *provider) CreateDNSRecord(ctx context.Context, zone string, in dns.RecordInput) (string, error) {
	z, err := p.zone(ctx, zone)
	if err != nil {
		return "", err
	}
	host, err := dnsutil.RelativeName(in.Name, z.Name)
	if err != nil {
		return "", err
	}
	codes, err := routeCodes(in.Line)
	if err != nil {
		return "", err
	}
	q := struct {
		recordData
		NSDomainID   json.Number `json:"nsDomainId"`
		NSRouteCodes []string    `json:"nsRouteCodes"`
	}{recordData{Name: host, Type: in.Type, Value: in.Content, TTL: in.TTL}, z.ID, codes}
	if in.Weight != nil {
		q.Weight = *in.Weight
	}
	if in.Priority != nil && in.Type == "MX" {
		q.MXPriority = *in.Priority
	}
	q.Description = in.Description
	if err := q.setContent(in.Content); err != nil {
		return "", err
	}
	var r struct{ NSRecordID json.Number }
	if err := p.call(ctx, "/NSRecordService/createNSRecord", q, &r); err != nil {
		return "", err
	}
	if _, err := dnsutil.PositiveID(r.NSRecordID.String()); err != nil {
		return "", selfhostutil.ErrProvider
	}
	return r.NSRecordID.String(), nil
}

func (p *provider) update(ctx context.Context, r *nsRecord) error {
	q := struct {
		recordData
		NSRecordID   json.Number `json:"nsRecordId"`
		NSRouteCodes []string    `json:"nsRouteCodes"`
		IsOn         bool        `json:"isOn"`
	}{r.recordData, r.ID, r.codes(), r.IsOn}
	return p.call(ctx, "/NSRecordService/updateNSRecord", q, nil)
}

func (p *provider) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	defer selfhostutil.LockZone(p.rpc.Base, zone)()
	row, err := p.record(ctx, zone, id)
	if err != nil {
		return "", err
	}
	if err := row.setContent(in.Content); err != nil {
		return "", err
	}
	row.TTL = in.TTL
	if err := p.update(ctx, row); err != nil {
		return "", err
	}
	return id, nil
}

func (p *provider) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	defer selfhostutil.LockZone(p.rpc.Base, zone)()
	row, err := p.record(ctx, zone, id)
	if err != nil {
		return "", err
	}
	if err := p.call(ctx, "/NSRecordService/deleteNSRecord", map[string]json.Number{"nsRecordId": row.ID}, nil); err != nil {
		return "", err
	}
	return id, nil
}

func (p *provider) BatchFields() []string { return []string{"status", "line", "weight", "remark"} }
func (p *provider) BatchAttribute(ctx context.Context, zone, id, field string) (string, error) {
	r, err := p.record(ctx, zone, id)
	if err != nil {
		return "", err
	}
	switch field {
	case "status":
		return r.status(), nil
	case "line":
		return strings.Join(r.codes(), ","), nil
	case "weight":
		return strconv.Itoa(r.Weight), nil
	case "remark":
		return r.Description, nil
	default:
		return "", dns.ErrInvalidDNSRequest
	}
}

func (p *provider) SetBatchAttribute(ctx context.Context, zone, id, field, value string) error {
	defer selfhostutil.LockZone(p.rpc.Base, zone)()
	r, err := p.record(ctx, zone, id)
	if err != nil {
		return err
	}
	switch field {
	case "status":
		if value != "enabled" && value != "disabled" {
			return dns.ErrInvalidDNSRequest
		}
		r.IsOn = value == "enabled"
	case "weight":
		weight, err := strconv.ParseInt(value, 10, 32)
		if err != nil || weight < 0 {
			return dns.ErrInvalidDNSRequest
		}
		r.Weight = int(weight)
	case "remark":
		r.Description = value
	case "line":
		codes, err := routeCodes(value)
		if err != nil {
			return err
		}
		r.NSRoutes = nil
		for _, c := range codes {
			r.NSRoutes = append(r.NSRoutes, route{Code: c})
		}
	default:
		return dns.ErrInvalidDNSRequest
	}
	return p.update(ctx, r)
}

func (r recordData) priority() *int {
	switch r.Type {
	case "MX":
		return &r.MXPriority
	case "SRV":
		return &r.SRVPriority
	}
	return nil
}
func (r recordData) content() string {
	switch r.Type {
	case "SRV":
		return fmt.Sprintf("%d %d %d %s", r.SRVPriority, r.SRVWeight, r.SRVPort, r.Value)
	case "CAA":
		return fmt.Sprintf("%d %s %s", r.CAAFlag, r.CAATag, strconv.Quote(r.Value))
	}
	return r.Value
}
func (r *recordData) setContent(value string) error {
	parts := strings.Fields(value)
	switch r.Type {
	case "SRV":
		if len(parts) != 4 {
			return dns.ErrInvalidDNSRequest
		}
		for i, field := range []*int{&r.SRVPriority, &r.SRVWeight, &r.SRVPort} {
			n, err := strconv.ParseUint(parts[i], 10, 16)
			if err != nil {
				return dns.ErrInvalidDNSRequest
			}
			*field = int(n)
		}
		value = parts[3]
	case "CAA":
		if len(parts) < 3 {
			return dns.ErrInvalidDNSRequest
		}
		n, err := strconv.ParseUint(parts[0], 10, 8)
		if err != nil {
			return dns.ErrInvalidDNSRequest
		}
		r.CAAFlag = int(n)
		r.CAATag = parts[1]
		value = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), parts[0])), parts[1]))
		if strings.HasPrefix(value, "\"") {
			v, err := strconv.Unquote(value)
			if err != nil {
				return dns.ErrInvalidDNSRequest
			}
			value = v
		}
	case "MX":
		if len(parts) == 2 {
			n, err := strconv.ParseUint(parts[0], 10, 16)
			if err != nil {
				return dns.ErrInvalidDNSRequest
			}
			r.MXPriority = int(n)
			value = parts[1]
		}
	}
	r.Value = value
	return nil
}
