package dnsmanagement

import (
	"context"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	"github.com/alibabacloud-go/tea/dara"
	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	ali "github.com/go-acme/alidns-20150109/v5/client"
	"strings"
	"time"
)

type Aliyun struct {
	sdk   *ali.Client
	group string
}

func NewAliyun(a *domain.Access) (*Aliyun, error) {
	id, secret := accountField(a, "accessKeyId"), accountField(a, "accessKeySecret")
	if id == "" || secret == "" {
		return nil, domain.ErrInvalidParams
	}
	c, err := ali.NewClient(&openapi.Config{AccessKeyId: &id, AccessKeySecret: &secret, Endpoint: ptr("alidns.aliyuncs.com"), RegionId: ptr("cn-hangzhou"), ConnectTimeout: ptr(5000), ReadTimeout: ptr(20000), HttpClient: dnsutil.AlibabaHTTPClient{Client: dnsutil.HTTPClientFor(a)}})
	if err != nil {
		return nil, providerError("Aliyun")
	}
	return &Aliyun{c, accountField(a, "resourceGroupId")}, nil
}
func (p *Aliyun) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	req := &ali.DescribeDomainsRequest{PageNumber: ptr(int64(page)), PageSize: ptr(int64(dns.DNSPageSize))}
	if p.group != "" {
		req.ResourceGroupId = &p.group
	}
	r, err := ali.DescribeDomainsWithContext(ctx, p.sdk, req, &dara.RuntimeOptions{})
	if err != nil || r == nil || r.Body == nil {
		return nil, providerError("Aliyun")
	}
	b := r.Body
	out := newPage[dns.Zone](page, int(val(b.TotalCount)))
	if b.Domains != nil {
		for _, row := range b.Domains.Domain {
			if row == nil {
				continue
			}
			name := val(row.DomainName)
			status := "active"
			if val(row.InstanceExpired) {
				status = "expired"
			}
			out.Items = append(out.Items, dns.Zone{ID: name, Name: name, Status: status})
		}
	}
	return out, nil
}
func (p *Aliyun) zone(ctx context.Context, zone string) (string, error) {
	z, err := zoneName(zone)
	if err != nil || p.group == "" {
		return z, err
	}
	r, err := ali.DescribeDomainInfoWithContext(ctx, p.sdk, &ali.DescribeDomainInfoRequest{DomainName: &z}, &dara.RuntimeOptions{})
	if err != nil || r == nil || r.Body == nil {
		return "", providerError("Aliyun")
	}
	if !strings.EqualFold(val(r.Body.DomainName), z) || val(r.Body.ResourceGroupId) != p.group {
		return "", domain.ErrRecordNotFound
	}
	return z, nil
}
func (p *Aliyun) DNSRecords(ctx context.Context, zone string, page int, filter string) (*dns.DNSPage[dns.DNSRecord], error) {
	z, err := p.zone(ctx, zone)
	if err != nil {
		return nil, err
	}
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	req := &ali.DescribeDomainRecordsRequest{DomainName: &z, PageNumber: ptr(int64(page)), PageSize: ptr(int64(dns.DNSPageSize))}
	if filter != "" {
		rr := strings.TrimSuffix(filter, "."+z)
		if filter == z {
			rr = "@"
		}
		req.RRKeyWord = &rr
		req.SearchMode = ptr("LIKE")
	}
	r, err := ali.DescribeDomainRecordsWithContext(ctx, p.sdk, req, &dara.RuntimeOptions{})
	if err != nil || r == nil || r.Body == nil {
		return nil, providerError("Aliyun")
	}
	if r.Body.TotalCount == nil || (val(r.Body.TotalCount) > int64((page-1)*dns.DNSPageSize) && r.Body.DomainRecords == nil) {
		return nil, providerError("Aliyun")
	}
	out := newPage[dns.DNSRecord](page, int(val(r.Body.TotalCount)))
	if r.Body.DomainRecords != nil {
		for _, v := range r.Body.DomainRecords.Record {
			if v == nil || val(v.RecordId) == "" || val(v.RR) == "" || val(v.Type) == "" || (v.DomainName != nil && !strings.EqualFold(*v.DomainName, z)) {
				return nil, providerError("Aliyun")
			}
			updated := ""
			if v.UpdateTimestamp != nil {
				updated = time.UnixMilli(*v.UpdateTimestamp).UTC().Format(time.RFC3339)
			}
			out.Items = append(out.Items, dns.DNSRecord{ID: val(v.RecordId), Name: fullName(val(v.RR), z), Type: val(v.Type), Content: val(v.Value), TTL: int(val(v.TTL)), Line: val(v.Line), Status: val(v.Status), UpdatedAt: updated, ReadOnly: val(v.Locked), Description: val(v.Remark), Weight: intPtr(v.Weight), Priority: intPtr(v.Priority)})
		}
	}
	return out, nil
}
func (p *Aliyun) CreateDNSRecord(ctx context.Context, zone string, in dns.RecordInput) (string, error) {
	z, err := p.zone(ctx, zone)
	if err != nil {
		return "", err
	}
	rr, err := relative(in.Name, z)
	if err != nil {
		return "", err
	}
	if in.Description != "" || in.Weight != nil {
		return "", dns.ErrInvalidDNSRequest
	}
	req := &ali.AddDomainRecordRequest{DomainName: &z, RR: &rr, Type: &in.Type, Value: &in.Content, TTL: ptr(int64(in.TTL))}
	if in.Type == "MX" {
		priority := 1
		if in.Priority != nil {
			priority = *in.Priority
		}
		if priority < 1 || priority > 50 {
			return "", dns.ErrInvalidDNSRequest
		}
		req.Priority = ptr(int64(priority))
	} else if in.Priority != nil {
		return "", dns.ErrInvalidDNSRequest
	}
	if in.Line != "" {
		line := in.Line
		if l, ok := aliyunLines[line]; ok {
			line = l
		}
		req.Line = &line
	}
	r, err := ali.AddDomainRecordWithContext(ctx, p.sdk, req, &dara.RuntimeOptions{})
	if err != nil || r == nil || r.Body == nil || val(r.Body.RecordId) == "" {
		return "", providerError("Aliyun")
	}
	return *r.Body.RecordId, nil
}

// AliDNS edits and deletes by account-wide record ID. Resolve its actual zone before either write.
func (p *Aliyun) record(ctx context.Context, zone, id string) (*ali.DescribeDomainRecordInfoResponseBody, error) {
	z, err := p.zone(ctx, zone)
	if err != nil {
		return nil, err
	}
	r, err := ali.DescribeDomainRecordInfoWithContext(ctx, p.sdk, &ali.DescribeDomainRecordInfoRequest{RecordId: &id}, &dara.RuntimeOptions{})
	if err != nil || r == nil || r.Body == nil {
		return nil, providerError("Aliyun")
	}
	if !strings.EqualFold(val(r.Body.DomainName), z) || val(r.Body.RecordId) != id {
		return nil, domain.ErrRecordNotFound
	}
	return r.Body, nil
}
func (p *Aliyun) writableRecord(ctx context.Context, zone, id string) (*ali.DescribeDomainRecordInfoResponseBody, error) {
	b, err := p.record(ctx, zone, id)
	if err != nil {
		return nil, err
	}
	if val(b.Type) == "" || val(b.RR) == "" || val(b.Line) == "" || b.Locked == nil {
		return nil, providerError("Aliyun")
	}
	if val(b.Locked) {
		return nil, dns.ErrInvalidDNSRequest
	}
	return b, nil
}
func (p *Aliyun) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	old, err := p.writableRecord(ctx, zone, id)
	if err != nil {
		return "", err
	}
	if val(old.Type) == "" || val(old.RR) == "" || val(old.Line) == "" || old.Type != nil && *old.Type == "MX" && old.Priority == nil {
		return "", providerError("Aliyun")
	}
	req := &ali.UpdateDomainRecordRequest{RecordId: &id, RR: old.RR, Type: old.Type, Line: old.Line, Value: &in.Content, TTL: ptr(int64(in.TTL))}
	if val(old.Type) == "MX" {
		req.Priority = old.Priority
	}
	r, err := ali.UpdateDomainRecordWithContext(ctx, p.sdk, req, &dara.RuntimeOptions{})
	if err != nil || r == nil || r.Body == nil || val(r.Body.RecordId) != id {
		return "", providerError("Aliyun")
	}
	return id, nil
}
func (p *Aliyun) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	if _, err := p.writableRecord(ctx, zone, id); err != nil {
		return "", err
	}
	r, err := ali.DeleteDomainRecordWithContext(ctx, p.sdk, &ali.DeleteDomainRecordRequest{RecordId: &id}, &dara.RuntimeOptions{})
	if err != nil || r == nil || r.Body == nil || val(r.Body.RecordId) != id {
		return "", providerError("Aliyun")
	}
	return id, nil
}

var aliyunLines = map[string]string{"0": "default", "10=1": "unicom", "10=0": "telecom", "10=3": "mobile", "10=2": "edu", "3=0": "oversea", "10=22": "btvn", "80=0": "search", "7=0": "internal"}

func (p *Aliyun) CreateZone(ctx context.Context, name string) (*dns.Zone, error) {
	z, err := zoneName(name)
	if err != nil {
		return nil, err
	}
	req := &ali.AddDomainRequest{DomainName: &z}
	if p.group != "" {
		req.ResourceGroupId = &p.group
	}
	r, err := ali.AddDomainWithContext(ctx, p.sdk, req, &dara.RuntimeOptions{})
	if err != nil || r == nil || r.Body == nil || !strings.EqualFold(val(r.Body.DomainName), z) || val(r.Body.DomainId) == "" {
		return nil, providerError("Aliyun")
	}
	return &dns.Zone{ID: z, Name: z}, nil
}
