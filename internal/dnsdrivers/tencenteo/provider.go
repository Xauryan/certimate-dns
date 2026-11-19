// Package tencenteo manages authoritative DNS records for NS-mode EdgeOne sites.
package tencenteo

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	teo "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/teo/v20220901"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

const (
	mainlandHost      = "teo.tencentcloudapi.com"
	internationalHost = "teo.intl.tencentcloudapi.com"
)

var errProvider = errors.New("EdgeOne DNS request failed; refresh before retrying a change")

type provider struct{ sdk *teo.Client }

func New(a *domain.Access) (dns.Provider, error) {
	if a == nil {
		return nil, domain.ErrInvalidParams
	}
	id, _ := a.Config["secretId"].(string)
	key, _ := a.Config["secretKey"].(string)
	if strings.TrimSpace(id) == "" || strings.TrimSpace(key) == "" {
		return nil, domain.ErrInvalidParams
	}
	host := mainlandHost
	switch a.Config["siteType"] {
	case nil, "", "cn":
	case "intl":
		host = internationalHost
	default:
		return nil, domain.ErrInvalidParams
	}
	prof := profile.NewClientProfile()
	prof.HttpProfile.Endpoint = host
	prof.HttpProfile.ReqTimeout = 25
	sdk, err := teo.NewClient(common.NewCredential(id, key), "", prof)
	if err != nil {
		return nil, errProvider
	}
	sdk.WithHttpTransport(dnsutil.SignedTransportFor(a, host))
	return &provider{sdk: sdk}, nil
}

func val[T any](p *T) (v T) {
	if p != nil {
		return *p
	}
	return v
}
func ptr[T any](v T) *T { return &v }

func filter(name, value string) *teo.AdvancedFilter {
	return &teo.AdvancedFilter{Name: &name, Values: []*string{&value}}
}

func pageOffset(page int) (*int64, error) {
	if page < 1 || page > 10000000 {
		return nil, dns.ErrInvalidDNSRequest
	}
	return ptr(int64(page-1) * dns.DNSPageSize), nil
}

func completePage(offset int64, total *int64, count int) bool {
	return total != nil && *total >= 0 && int64(count) == min(dns.DNSPageSize, max(0, *total-offset))
}

func (p *provider) zones(ctx context.Context, page int, id string) (*dns.DNSPage[dns.Zone], error) {
	offset, err := pageOffset(page)
	if err != nil {
		return nil, err
	}
	req := teo.NewDescribeZonesRequest()
	req.Offset, req.Limit = offset, ptr(int64(dns.DNSPageSize))
	req.Filters = []*teo.AdvancedFilter{filter("zone-type", "full")}
	if id != "" {
		req.Filters = append(req.Filters, filter("zone-id", id))
	}
	r, err := p.sdk.DescribeZonesWithContext(ctx, req)
	if err != nil || r == nil || r.Response == nil || !completePage(*offset, r.Response.TotalCount, len(r.Response.Zones)) {
		return nil, errProvider
	}
	out := &dns.DNSPage[dns.Zone]{Items: []dns.Zone{}, Info: dns.PageInfo{Page: page, Total: int(*r.Response.TotalCount)}}
	for _, z := range r.Response.Zones {
		if z == nil || val(z.Type) != "full" || val(z.ZoneId) == "" || val(z.ZoneName) == "" || (id != "" && val(z.ZoneId) != id) {
			return nil, errProvider
		}
		name, err := dnsutil.ZoneName(*z.ZoneName)
		if err != nil {
			return nil, errProvider
		}
		out.Items = append(out.Items, dns.Zone{ID: *z.ZoneId, Name: name, Status: val(z.Status)})
	}
	return out, nil
}

func (p *provider) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	return p.zones(ctx, page, "")
}

func (p *provider) zone(ctx context.Context, id string) (dns.Zone, error) {
	if id == "" {
		return dns.Zone{}, dns.ErrInvalidDNSRequest
	}
	out, err := p.zones(ctx, 1, id)
	if err != nil {
		return dns.Zone{}, err
	}
	if len(out.Items) != 1 || out.Info.Total != 1 {
		return dns.Zone{}, domain.ErrRecordNotFound
	}
	return out.Items[0], nil
}

func ownerName(input, zone string) (string, error) {
	host, err := dnsutil.RelativeName(input, zone)
	if err != nil {
		return "", err
	}
	return dnsutil.FullName(host, zone), nil
}

func (p *provider) ZoneDetails(ctx context.Context, id string) (*dns.ZoneDetails, error) {
	z, err := p.zone(ctx, id)
	if err != nil {
		return nil, err
	}
	return &dns.ZoneDetails{Name: z.Name, Status: z.Status, MinTTL: 60, Lines: []dns.RecordLine{{ID: "Default", Name: "默认"}}}, nil
}

func (p *provider) records(ctx context.Context, z dns.Zone, page int, f *teo.AdvancedFilter) (*teo.DescribeDnsRecordsResponseParams, error) {
	offset, err := pageOffset(page)
	if err != nil {
		return nil, err
	}
	req := teo.NewDescribeDnsRecordsRequest()
	req.ZoneId, req.Offset, req.Limit = &z.ID, offset, ptr(int64(dns.DNSPageSize))
	if f != nil {
		req.Filters = []*teo.AdvancedFilter{f}
	}
	r, err := p.sdk.DescribeDnsRecordsWithContext(ctx, req)
	if err != nil || r == nil || r.Response == nil || !completePage(*offset, r.Response.TotalCount, len(r.Response.DnsRecords)) {
		return nil, errProvider
	}
	for _, row := range r.Response.DnsRecords {
		if row == nil || val(row.ZoneId) != z.ID || val(row.RecordId) == "" || val(row.Name) == "" || val(row.Type) == "" {
			return nil, errProvider
		}
		if row.Content == nil || row.TTL == nil || (*row.Type == "MX" && row.Priority == nil) {
			return nil, errProvider
		}
		if _, err := ownerName(*row.Name, z.Name); err != nil {
			return nil, errProvider
		}
	}
	return r.Response, nil
}

func (p *provider) DNSRecords(ctx context.Context, zone string, page int, name string) (*dns.DNSPage[dns.DNSRecord], error) {
	z, err := p.zone(ctx, zone)
	if err != nil {
		return nil, err
	}
	var f *teo.AdvancedFilter
	if name != "" {
		if name == "@" {
			name = z.Name
		}
		f = filter("name", name)
		f.Fuzzy = ptr(true)
	}
	b, err := p.records(ctx, z, page, f)
	if err != nil {
		return nil, err
	}
	out := &dns.DNSPage[dns.DNSRecord]{Items: []dns.DNSRecord{}, Info: dns.PageInfo{Page: page, Total: int(*b.TotalCount)}}
	for _, r := range b.DnsRecords {
		row := dns.DNSRecord{ID: *r.RecordId, Name: *r.Name, Type: *r.Type, Content: val(r.Content), TTL: int(val(r.TTL)), Line: val(r.Location), Status: val(r.Status)}
		if updated, err := time.Parse(time.RFC3339, val(r.ModifiedOn)); err == nil {
			row.UpdatedAt = updated.UTC().Format(time.RFC3339)
		}
		if r.Weight != nil && *r.Weight >= 0 {
			row.Weight = ptr(int(*r.Weight))
		}
		if r.Priority != nil && *r.Type == "MX" {
			row.Priority = ptr(int(*r.Priority))
		}
		out.Items = append(out.Items, row)
	}
	return out, nil
}

func (p *provider) record(ctx context.Context, zone, id string) (*teo.DnsRecord, error) {
	if id == "" {
		return nil, dns.ErrInvalidDNSRequest
	}
	z, err := p.zone(ctx, zone)
	if err != nil {
		return nil, err
	}
	b, err := p.records(ctx, z, 1, filter("id", id))
	if err != nil {
		return nil, err
	}
	if len(b.DnsRecords) != 1 || *b.TotalCount != 1 || *b.DnsRecords[0].RecordId != id {
		return nil, domain.ErrRecordNotFound
	}
	return b.DnsRecords[0], nil
}

func (p *provider) CreateDNSRecord(ctx context.Context, zone string, in dns.RecordInput) (string, error) {
	if in.Content == "" || in.TTL < 60 || in.TTL > 86400 || in.Description != "" {
		return "", dns.ErrInvalidDNSRequest
	}
	switch in.Type {
	case "A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA":
	default:
		return "", dns.ErrInvalidDNSRequest
	}
	if in.Priority != nil && (in.Type != "MX" || *in.Priority < 0 || *in.Priority > 50) {
		return "", dns.ErrInvalidDNSRequest
	}
	if in.Weight != nil && ((*in.Weight < -1 || *in.Weight > 100) || (in.Type != "A" && in.Type != "AAAA" && in.Type != "CNAME")) {
		return "", dns.ErrInvalidDNSRequest
	}
	z, err := p.zone(ctx, zone)
	if err != nil {
		return "", err
	}
	name, err := ownerName(in.Name, z.Name)
	if err != nil {
		return "", err
	}
	req := teo.NewCreateDnsRecordRequest()
	req.ZoneId, req.Name, req.Type, req.Content, req.TTL = &zone, &name, &in.Type, &in.Content, ptr(int64(in.TTL))
	if in.Line != "" && !strings.EqualFold(in.Line, "default") {
		if in.Type != "A" && in.Type != "AAAA" && in.Type != "CNAME" {
			return "", dns.ErrInvalidDNSRequest
		}
		req.Location = &in.Line
	}
	if in.Type == "MX" {
		// EdgeOne's default MX preference is zero.
		target, priority, err := dnsutil.MXParts(in.Content, in.Priority, 0, 50)
		if err != nil {
			return "", err
		}
		req.Priority, req.Content = ptr(int64(priority)), &target
	}
	if in.Weight != nil {
		req.Weight = ptr(int64(*in.Weight))
	}
	r, err := p.sdk.CreateDnsRecordWithContext(ctx, req)
	if err != nil || r == nil || r.Response == nil || val(r.Response.RecordId) == "" {
		return "", errProvider
	}
	return *r.Response.RecordId, nil
}

func (p *provider) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	if in.Content == "" || in.TTL < 60 || in.TTL > 86400 {
		return "", dns.ErrInvalidDNSRequest
	}
	old, err := p.record(ctx, zone, id)
	if err != nil {
		return "", err
	}
	if *old.Type == "MX" {
		target, priority, err := dnsutil.MXParts(in.Content, nil, int(*old.Priority), 50)
		if err != nil {
			return "", err
		}
		old.Priority, in.Content = ptr(int64(priority)), target
	}
	old.Content, old.TTL = &in.Content, ptr(int64(in.TTL))
	if err := p.modify(ctx, zone, old); err != nil {
		return "", err
	}
	return id, nil
}

func (p *provider) modify(ctx context.Context, zone string, r *teo.DnsRecord) error {
	req := teo.NewModifyDnsRecordsRequest()
	req.ZoneId = &zone
	req.DnsRecords = []*teo.DnsRecord{{RecordId: r.RecordId, Name: r.Name, Type: r.Type, Location: r.Location, Priority: r.Priority, Weight: r.Weight, Content: r.Content, TTL: r.TTL}}
	res, err := p.sdk.ModifyDnsRecordsWithContext(ctx, req)
	if err != nil || res == nil || res.Response == nil || val(res.Response.RequestId) == "" {
		return errProvider
	}
	return nil
}

func (p *provider) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	if _, err := p.record(ctx, zone, id); err != nil {
		return "", err
	}
	req := teo.NewDeleteDnsRecordsRequest()
	req.ZoneId, req.RecordIds = &zone, []*string{&id}
	r, err := p.sdk.DeleteDnsRecordsWithContext(ctx, req)
	if err != nil || r == nil || r.Response == nil || val(r.Response.RequestId) == "" {
		return "", errProvider
	}
	return id, nil
}

func (p *provider) BatchFields() []string { return []string{"status", "weight", "line"} }

func (p *provider) BatchAttribute(ctx context.Context, zone, id, field string) (string, error) {
	r, err := p.record(ctx, zone, id)
	if err != nil {
		return "", err
	}
	switch field {
	case "status":
		switch val(r.Status) {
		case "enable":
			return "enabled", nil
		case "disable":
			return "disabled", nil
		}
	case "weight":
		if r.Weight == nil || *r.Weight == -1 {
			return "", nil
		}
		return strconv.FormatInt(*r.Weight, 10), nil
	case "line":
		if val(r.Location) == "" {
			return "Default", nil
		}
		return *r.Location, nil
	}
	return "", dns.ErrInvalidDNSRequest
}

func (p *provider) SetBatchAttribute(ctx context.Context, zone, id, field, value string) error {
	r, err := p.record(ctx, zone, id)
	if err != nil {
		return err
	}
	if field == "status" {
		req := teo.NewModifyDnsRecordsStatusRequest()
		req.ZoneId = &zone
		switch value {
		case "enabled":
			req.RecordsToEnable = []*string{&id}
		case "disabled":
			req.RecordsToDisable = []*string{&id}
		default:
			return dns.ErrInvalidDNSRequest
		}
		res, err := p.sdk.ModifyDnsRecordsStatusWithContext(ctx, req)
		if err != nil || res == nil || res.Response == nil || val(res.Response.RequestId) == "" {
			return errProvider
		}
		return nil
	}
	switch *r.Type {
	case "A", "AAAA", "CNAME":
	default:
		return dns.ErrInvalidDNSRequest
	}
	switch field {
	case "weight":
		var weight int64 = -1
		if value != "" {
			weight, err = strconv.ParseInt(value, 10, 64)
			if err != nil || weight < -1 || weight > 100 {
				return dns.ErrInvalidDNSRequest
			}
		}
		r.Weight = &weight
	case "line":
		if strings.TrimSpace(value) == "" {
			return dns.ErrInvalidDNSRequest
		}
		r.Location = &value
	default:
		return dns.ErrInvalidDNSRequest
	}
	return p.modify(ctx, zone, r)
}
