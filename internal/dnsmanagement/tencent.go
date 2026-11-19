package dnsmanagement

import (
	"context"
	"errors"
	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	tc "github.com/go-acme/tencentclouddnspod/v20210323"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tcerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	"regexp"
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
	const endpoint = "dnspod.tencentcloudapi.com"
	prof.HttpProfile.Endpoint = endpoint
	prof.HttpProfile.ReqTimeout = 25
	c, err := tc.NewClient(common.NewCredential(id, secret), "", prof)
	if err != nil {
		return nil, providerError("DNSPod")
	}
	c.WithHttpTransport(dnsutil.SignedTransportFor(a, endpoint))
	return &Tencent{c}, nil
}
func (p *Tencent) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
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
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
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
	if b.RecordCountInfo.TotalCount == nil {
		return nil, providerError("DNSPod")
	}
	out := newPage[dns.DNSRecord](page, int(val(b.RecordCountInfo.TotalCount)))
	for _, v := range b.RecordList {
		if v == nil || val(v.RecordId) == 0 || val(v.Type) == "" || val(v.Name) == "" {
			return nil, providerError("DNSPod")
		}
		line := val(v.LineId)
		if line == "" {
			line = val(v.Line)
		}
		out.Items = append(out.Items, dns.DNSRecord{ID: strconv.FormatUint(val(v.RecordId), 10), Name: fullName(val(v.Name), z), Type: normalizedTencentType(val(v.Type)), Content: val(v.Value), TTL: int(val(v.TTL)), Line: line, Status: val(v.Status), Description: val(v.Remark), ReadOnly: val(v.DefaultNS) || (val(v.Type) == "NS" && val(v.Name) == "@"), UpdatedAt: val(v.UpdatedOn), Weight: intPtr(v.Weight), Priority: intPtr(v.MX)})
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
	if in.Line != "" {
		switch {
		case tencentLineID.MatchString(in.Line):
			req.RecordLineId = &in.Line
		case strings.HasPrefix(in.Line, "N."):
			req.RecordLine = ptr(strings.TrimPrefix(in.Line, "N."))
		default:
			req.RecordLine = &in.Line
		}
	}
	if in.Description != "" {
		req.Remark = &in.Description
	}
	if in.Weight != nil {
		if *in.Weight < 0 || *in.Weight > 100 {
			return "", dns.ErrInvalidDNSRequest
		}
		req.Weight = ptr(uint64(*in.Weight))
	}
	if in.Type == "MX" {
		priority := 1
		if in.Priority != nil {
			priority = *in.Priority
		}
		if priority < 1 || priority > 65535 {
			return "", dns.ErrInvalidDNSRequest
		}
		req.MX = ptr(uint64(priority))
	} else if in.Priority != nil {
		return "", dns.ErrInvalidDNSRequest
	}
	req.RecordType = ptr(nativeTencentType(in.Type))
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
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != id {
		return "", 0, dns.ErrInvalidDNSRequest
	}
	return z, n, nil
}
func (p *Tencent) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	z, n, err := recordKey(zone, id)
	if err != nil {
		return "", err
	}
	old, err := p.writableRecord(ctx, z, n)
	if err != nil {
		return "", err
	}
	if val(old.RecordLine) == "" || old.Enabled == nil || (val(old.RecordType) == "MX" && old.MX == nil) {
		return "", providerError("DNSPod")
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
	if _, err = p.writableRecord(ctx, z, n); err != nil {
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

var tencentLineID = regexp.MustCompile(`^[0-9]+(=[0-9]+)?$`)

func nativeTencentType(typ string) string {
	switch typ {
	case "REDIRECT_URL":
		return "显性URL"
	case "FORWARD_URL":
		return "隐性URL"
	}
	return typ
}
func normalizedTencentType(typ string) string {
	switch typ {
	case "显性URL":
		return "REDIRECT_URL"
	case "隐性URL":
		return "FORWARD_URL"
	}
	return typ
}
func (p *Tencent) writableRecord(ctx context.Context, z string, id uint64) (*tc.RecordInfo, error) {
	b, err := p.advancedRecord(ctx, z, id)
	if err != nil {
		return nil, err
	}
	if val(b.RecordType) == "" || val(b.SubDomain) == "" {
		return nil, providerError("DNSPod")
	}
	if *b.RecordType == "NS" && *b.SubDomain == "@" {
		return nil, dns.ErrInvalidDNSRequest
	}
	return b, nil
}
func (p *Tencent) CreateZone(ctx context.Context, name string) (*dns.Zone, error) {
	z, err := zoneName(name)
	if err != nil {
		return nil, err
	}
	req := tc.NewCreateDomainRequest()
	req.Domain = &z
	r, err := tc.CreateDomainWithContext(ctx, p.sdk, req)
	if err != nil || r == nil || r.Response == nil || r.Response.DomainInfo == nil {
		return nil, providerError("DNSPod")
	}
	b := r.Response.DomainInfo
	if val(b.Id) == 0 || (!strings.EqualFold(val(b.Domain), z) && !strings.EqualFold(val(b.Punycode), z)) {
		return nil, providerError("DNSPod")
	}
	return &dns.Zone{ID: z, Name: z}, nil
}
