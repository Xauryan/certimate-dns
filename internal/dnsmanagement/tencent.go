package dnsmanagement

import (
	"context"
	"errors"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	tc "github.com/go-acme/tencentclouddnspod/v20210323"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tcerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	"strconv"
	"strings"
)

type Tencent struct{ sdk *tc.Client }

func NewTencent(a *domain.Access) (*Tencent, error) {
	id, secret := accountField(a, "secretId"), accountField(a, "secretKey")
	if id == "" || secret == "" {
		return nil, domain.ErrInvalidParams
	}
	prof := profile.NewClientProfile()
	prof.HttpProfile.ReqTimeout = 25
	c, err := tc.NewClient(common.NewCredential(id, secret), "", prof)
	if err != nil {
		return nil, providerError("DNSPod")
	}
	return &Tencent{c}, nil
}
func (p *Tencent) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	req := tc.NewDescribeDomainListRequest()
	req.Offset = ptr(int64(page-1) * dns.DNSPageSize)
	req.Limit = ptr(int64(dns.DNSPageSize))
	r, err := tc.DescribeDomainListWithContext(ctx, p.sdk, req)
	if err != nil || r == nil || r.Response == nil || r.Response.DomainCountInfo == nil {
		return nil, providerError("DNSPod")
	}
	b := r.Response
	out := newPage[dns.Zone](page, int(val(b.DomainCountInfo.DomainTotal)))
	for _, row := range b.DomainList {
		if row != nil {
			out.Items = append(out.Items, dns.Zone{ID: val(row.Name), Name: val(row.Name), Status: val(row.Status)})
		}
	}
	return out, nil
}
func (p *Tencent) DNSRecords(ctx context.Context, zone string, page int, filter string) (*dns.DNSPage[dns.DNSRecord], error) {
	z, err := zoneName(zone)
	if err != nil {
		return nil, err
	}
	req := tc.NewDescribeRecordListRequest()
	req.Domain = &z
	req.Offset = ptr(uint64(page-1) * dns.DNSPageSize)
	req.Limit = ptr(uint64(dns.DNSPageSize))
	if filter != "" {
		q := strings.TrimSuffix(filter, "."+z)
		if filter == z {
			q = "@"
		}
		req.Keyword = &q
	}
	r, err := tc.DescribeRecordListWithContext(ctx, p.sdk, req)
	var sdkErr *tcerrors.TencentCloudSDKError
	if errors.As(err, &sdkErr) && sdkErr.Code == "ResourceNotFound.NoDataOfRecord" {
		return newPage[dns.DNSRecord](page, 0), nil
	}
	if err != nil || r == nil || r.Response == nil || r.Response.RecordCountInfo == nil {
		return nil, providerError("DNSPod")
	}
	b := r.Response
	out := newPage[dns.DNSRecord](page, int(val(b.RecordCountInfo.TotalCount)))
	for _, v := range b.RecordList {
		if v != nil {
			out.Items = append(out.Items, dns.DNSRecord{ID: strconv.FormatUint(val(v.RecordId), 10), Name: fullName(val(v.Name), z), Type: val(v.Type), Content: val(v.Value), TTL: int(val(v.TTL)), Line: val(v.Line), Status: val(v.Status)})
		}
	}
	return out, nil
}
func (p *Tencent) CreateDNSRecord(ctx context.Context, zone string, in dns.RecordInput) (string, error) {
	z, err := zoneName(zone)
	if err != nil {
		return "", err
	}
	rr, err := relative(in.Name, z)
	if err != nil {
		return "", err
	}
	req := tc.NewCreateRecordRequest()
	req.Domain = &z
	req.SubDomain = &rr
	req.RecordLine = ptr("默认")
	req.RecordType = &in.Type
	req.Value = &in.Content
	req.TTL = ptr(uint64(in.TTL))
	r, err := tc.CreateRecordWithContext(ctx, p.sdk, req)
	if err != nil || r == nil || r.Response == nil || val(r.Response.RecordId) == 0 {
		return "", providerError("DNSPod")
	}
	return strconv.FormatUint(*r.Response.RecordId, 10), nil
}
func recordKey(zone, id string) (string, uint64, error) {
	z, err := zoneName(zone)
	if err != nil {
		return "", 0, err
	}
	n, err := strconv.ParseUint(id, 10, 64)
	if err != nil || n == 0 {
		return "", 0, dns.ErrInvalidDNSRequest
	}
	return z, n, nil
}
func (p *Tencent) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	z, n, err := recordKey(zone, id)
	if err != nil {
		return "", err
	}
	get := tc.NewDescribeRecordRequest()
	get.Domain = &z
	get.RecordId = &n
	detail, err := tc.DescribeRecordWithContext(ctx, p.sdk, get)
	if err != nil || detail == nil || detail.Response == nil || detail.Response.RecordInfo == nil {
		return "", providerError("DNSPod")
	}
	old := detail.Response.RecordInfo
	if val(old.Id) != n {
		return "", domain.ErrRecordNotFound
	}
	req := tc.NewModifyRecordRequest()
	req.Domain = &z
	req.RecordId = &n
	req.SubDomain = old.SubDomain
	req.RecordType = old.RecordType
	req.RecordLine = old.RecordLine
	req.RecordLineId = old.RecordLineId
	req.Value = &in.Content
	req.TTL = ptr(uint64(in.TTL))
	req.Weight = old.Weight
	req.Remark = old.Remark
	if val(old.RecordType) == "MX" {
		req.MX = old.MX
	}
	if old.Enabled != nil {
		status := "DISABLE"
		if *old.Enabled == 1 {
			status = "ENABLE"
		}
		req.Status = &status
	}
	r, err := tc.ModifyRecordWithContext(ctx, p.sdk, req)
	if err != nil || r == nil || r.Response == nil || val(r.Response.RecordId) != n {
		return "", providerError("DNSPod")
	}
	return id, nil
}
func (p *Tencent) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	z, n, err := recordKey(zone, id)
	if err != nil {
		return "", err
	}
	req := tc.NewDeleteRecordRequest()
	req.Domain = &z
	req.RecordId = &n
	r, err := tc.DeleteRecordWithContext(ctx, p.sdk, req)
	if err != nil || r == nil || r.Response == nil || val(r.Response.RequestId) == "" {
		return "", providerError("DNSPod")
	}
	return id, nil
}
