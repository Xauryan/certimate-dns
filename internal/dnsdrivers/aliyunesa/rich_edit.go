package aliyunesa

import (
	"context"
	"strconv"

	"github.com/alibabacloud-go/tea/dara"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func (p *provider) RecordEditCapabilities() dns.RecordEditCapabilities {
	// Alibaba's ESA record resource identifies RecordName and RecordType as
	// immutable. An MX preference belongs to the updatable Data object.
	return dns.RecordEditCapabilities{Priority: true}
}

func (p *provider) ReplaceDNSRecord(ctx context.Context, zone string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	id, err := dnsutil.PositiveID(prior.ID)
	if err != nil {
		return "", err
	}
	s, err := p.site(ctx, zone)
	if err != nil {
		return "", err
	}
	r, err := p.recordInSite(ctx, s, id)
	if err != nil {
		return "", err
	}
	if r.Data == nil || r.RecordType == nil || r.Ttl == nil {
		return "", errProvider
	}
	host, err := dnsutil.RelativeName(*r.RecordName, s.name)
	if err != nil {
		return "", err
	}
	name, err := dnsutil.RelativeName(desired.Name, s.name)
	if err != nil || host != name {
		return "", dns.ErrInvalidDNSRequest
	}
	current, err := recordView(dns.DNSRecord{ID: strconv.FormatInt(*r.RecordId, 10), Name: dnsutil.FullName(host, s.name), Type: *r.RecordType, TTL: int(*r.Ttl), Proxied: dara.BoolValue(r.Proxied), Description: dara.StringValue(r.Comment)}, r.Data, r.UpdateTime)
	if err != nil {
		return "", err
	}
	if current.Type != desired.Type || (current.Type == "NS" && host == "@") {
		return "", dns.ErrInvalidDNSRequest
	}
	if err := dnsutil.CheckReplacement("aliyunesa", prior, current, desired); err != nil {
		return "", err
	}
	content := desired.Content
	if current.Type == "MX" {
		content, err = dnsutil.MXValue("MX", content, desired.Priority, current.Content)
		if err != nil {
			return "", err
		}
	}
	return p.patch(ctx, prior.ID, r, dns.RecordPatch{Content: content, TTL: desired.TTL})
}
