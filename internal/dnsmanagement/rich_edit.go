package dnsmanagement

import (
	"context"
	"strings"

	"github.com/alibabacloud-go/tea/dara"
	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	ali "github.com/go-acme/alidns-20150109/v5/client"
	tc "github.com/go-acme/tencentclouddnspod/v20210323"
)

var _ dns.RecordEditor = (*Aliyun)(nil)
var _ dns.RecordEditor = (*Tencent)(nil)

func (*Aliyun) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true}
}

func (*Tencent) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true}
}

func editOwner(provider, zone string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	cap, _ := dns.ProviderCapabilities(provider)
	if prior.ID == "" || prior.ReadOnly || !cap.AllowsType(desired.Type) || !cap.AllowsTTL(desired.TTL) || desired.Content == "" {
		return "", dns.ErrInvalidDNSRequest
	}
	return relative(desired.Name, zone)
}

func matchingVersion(prior dns.DNSRecord, owner, kind, content string, ttl int) bool {
	return strings.EqualFold(strings.TrimSuffix(prior.Name, "."), strings.TrimSuffix(owner, ".")) && prior.Type == kind && prior.Content == content && prior.TTL == ttl
}

func editValue(prior dns.DNSRecord, desired dns.RecordInput, oldPriority *int, maximum int) (string, *int, error) {
	if desired.Type != "MX" {
		if desired.Priority != nil {
			return "", nil, dns.ErrInvalidDNSRequest
		}
		return desired.Content, nil, nil
	}
	fallback := 1
	if prior.Type == "MX" {
		if oldPriority == nil || prior.Priority == nil || *oldPriority != *prior.Priority {
			return "", nil, dns.ErrInvalidDNSRequest
		}
		fallback = *oldPriority
	}
	target, priority, err := dnsutil.MXParts(desired.Content, desired.Priority, fallback, maximum)
	if err != nil || priority < 1 {
		return "", nil, dns.ErrInvalidDNSRequest
	}
	return target, &priority, nil
}

func (p *Aliyun) ReplaceDNSRecord(ctx context.Context, zone string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	name, err := editOwner("aliyun", zone, prior, desired)
	if err != nil {
		return "", err
	}
	old, err := p.writableRecord(ctx, zone, prior.ID)
	if err != nil {
		return "", err
	}
	if old.Value == nil || old.TTL == nil || !matchingVersion(prior, fullName(*old.RR, *old.DomainName), *old.Type, *old.Value, int(*old.TTL)) {
		return "", dns.ErrInvalidDNSRequest
	}
	current := prior
	current.Line = val(old.Line)
	current.Status = val(old.Status)
	current.Description = val(old.Remark)
	if current.Type == "MX" {
		current.Priority = intPtr(old.Priority)
	}
	if err := dnsutil.CheckReplacement("aliyun", prior, current, desired); err != nil {
		return "", err
	}
	if desired.Type != prior.Type && prior.Weight != nil && *prior.Weight > 0 {
		return "", dns.ErrInvalidDNSRequest
	}
	content, priority, err := editValue(prior, desired, intPtr(old.Priority), 50)
	if err != nil {
		return "", err
	}
	req := &ali.UpdateDomainRecordRequest{RecordId: &prior.ID, RR: &name, Type: &desired.Type, Value: &content, TTL: ptr(int64(desired.TTL)), Line: old.Line}
	if priority != nil {
		req.Priority = ptr(int64(*priority))
	}
	r, err := ali.UpdateDomainRecordWithContext(ctx, p.sdk, req, &dara.RuntimeOptions{})
	if err != nil || r == nil || r.Body == nil || val(r.Body.RecordId) != prior.ID {
		return "", providerError("Aliyun")
	}
	return prior.ID, nil
}

func (p *Tencent) ReplaceDNSRecord(ctx context.Context, zone string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	z, id, err := recordKey(zone, prior.ID)
	if err != nil {
		return "", err
	}
	name, err := editOwner("tencentcloud", z, prior, desired)
	if err != nil {
		return "", err
	}
	old, err := p.writableRecord(ctx, z, id)
	if err != nil {
		return "", err
	}
	if old.Value == nil || old.TTL == nil || old.Enabled == nil || *old.Enabled > 1 || val(old.RecordLine) == "" || !matchingVersion(prior, fullName(*old.SubDomain, z), normalizedTencentType(*old.RecordType), *old.Value, int(*old.TTL)) {
		return "", dns.ErrInvalidDNSRequest
	}
	current := prior
	current.Line = val(old.RecordLineId)
	if current.Line == "" {
		current.Line = *old.RecordLine
	}
	current.Description = val(old.Remark)
	current.Weight = intPtr(old.Weight)
	current.UpdatedAt = val(old.UpdatedOn)
	current.Status = "DISABLE"
	if *old.Enabled == 1 {
		current.Status = "ENABLE"
	}
	if current.Type == "MX" {
		current.Priority = intPtr(old.MX)
	}
	if err := dnsutil.CheckReplacement("tencentcloud", prior, current, desired); err != nil {
		return "", err
	}
	if (name == "@" && desired.Type == "NS") || (desired.Type != prior.Type && val(old.Weight) > 0) {
		return "", dns.ErrInvalidDNSRequest
	}
	content, priority, err := editValue(prior, desired, intPtr(old.MX), 65535)
	if err != nil {
		return "", err
	}
	req := tc.NewModifyRecordRequest()
	req.Domain = &z
	req.RecordId = &id
	req.SubDomain = &name
	req.RecordType = ptr(nativeTencentType(desired.Type))
	req.Value = &content
	req.TTL = ptr(uint64(desired.TTL))
	req.RecordLine = old.RecordLine
	req.RecordLineId = old.RecordLineId
	req.Weight = old.Weight
	req.Remark = old.Remark
	if priority != nil {
		req.MX = ptr(uint64(*priority))
	}
	req.Status = ptr("DISABLE")
	if *old.Enabled == 1 {
		req.Status = ptr("ENABLE")
	}
	r, err := tc.ModifyRecordWithContext(ctx, p.sdk, req)
	if err != nil || r == nil || r.Response == nil || val(r.Response.RecordId) != id {
		return "", providerError("DNSPod")
	}
	return prior.ID, nil
}
