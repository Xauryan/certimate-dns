package huoshan

import (
	"context"
	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func (*provider) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true}
}
func (p *provider) ReplaceDNSRecord(ctx context.Context, zone string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", err
	}
	r, err := p.record(ctx, z, prior.ID)
	if err != nil {
		return "", err
	}
	if err = dnsutil.CheckReplacement("volcengine", prior, r.row(z), desired); err != nil {
		return "", err
	}
	host, err := dnsutil.RelativeName(desired.Name, z)
	if err != nil {
		return "", err
	}
	previous := ""
	if r.Type == "MX" {
		previous = r.Value
	}
	content, err := dnsutil.MXValue(desired.Type, desired.Content, desired.Priority, previous)
	if err != nil {
		return "", err
	}
	if r.Weight != nil && (r.Type == "A" || r.Type == "AAAA" || r.Type == "CNAME") && desired.Type != "A" && desired.Type != "AAAA" && desired.Type != "CNAME" {
		return "", dns.ErrInvalidDNSRequest
	}
	if err = p.guardSiblings(ctx, r.zoneID, r.RecordID, host, desired.Type, r.Line, desired.TTL); err != nil {
		return "", err
	}
	r.Host, r.Type, r.Value, r.TTL = host, desired.Type, content, desired.TTL
	if err = p.update(ctx, r); err != nil {
		return "", err
	}
	return r.RecordID, nil
}
