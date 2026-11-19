package dnsmanagement

import (
	"context"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	"github.com/alibabacloud-go/tea/dara"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	ali "github.com/go-acme/alidns-20150109/v5/client"
	"strings"
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
	c, err := ali.NewClient(&openapi.Config{AccessKeyId: &id, AccessKeySecret: &secret, Endpoint: ptr("alidns.aliyuncs.com"), RegionId: ptr("cn-hangzhou"), ConnectTimeout: ptr(5000), ReadTimeout: ptr(20000)})
	if err != nil {
		return nil, providerError("Aliyun")
	}
	return &Aliyun{c, accountField(a, "resourceGroupId")}, nil
}
func (p *Aliyun) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
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
	if val(r.Body.ResourceGroupId) != p.group {
		return "", domain.ErrRecordNotFound
	}
	return z, nil
}
func (p *Aliyun) DNSRecords(ctx context.Context, zone string, page int, filter string) (*dns.DNSPage[dns.DNSRecord], error) {
	z, err := p.zone(ctx, zone)
	if err != nil {
		return nil, err
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
	out := newPage[dns.DNSRecord](page, int(val(r.Body.TotalCount)))
	if r.Body.DomainRecords != nil {
		for _, v := range r.Body.DomainRecords.Record {
			if v != nil {
				out.Items = append(out.Items, dns.DNSRecord{ID: val(v.RecordId), Name: fullName(val(v.RR), z), Type: val(v.Type), Content: val(v.Value), TTL: int(val(v.TTL)), Line: val(v.Line), Status: val(v.Status)})
			}
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
	r, err := ali.AddDomainRecordWithContext(ctx, p.sdk, &ali.AddDomainRecordRequest{DomainName: &z, RR: &rr, Type: &in.Type, Value: &in.Content, TTL: ptr(int64(in.TTL))}, &dara.RuntimeOptions{})
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
func (p *Aliyun) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	old, err := p.record(ctx, zone, id)
	if err != nil {
		return "", err
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
	if _, err := p.record(ctx, zone, id); err != nil {
		return "", err
	}
	r, err := ali.DeleteDomainRecordWithContext(ctx, p.sdk, &ali.DeleteDomainRecordRequest{RecordId: &id}, &dara.RuntimeOptions{})
	if err != nil || r == nil || r.Body == nil || val(r.Body.RecordId) != id {
		return "", providerError("Aliyun")
	}
	return id, nil
}
