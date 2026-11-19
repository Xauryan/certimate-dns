package jdcloud

import (
	"context"
	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func (*provider) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true}
}
func (p *provider) ReplaceDNSRecord(ctx context.Context, zone string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	z, r, err := p.current(ctx, zone, prior.ID)
	if err != nil {
		return "", err
	}
	if err = dnsutil.CheckReplacement("jdcloud", prior, r.row(z.DomainName), desired); err != nil {
		return "", err
	}
	host, err := dnsutil.RelativeName(desired.Name, z.DomainName)
	if err != nil {
		return "", err
	}
	previous := ""
	if r.Type == "MX" {
		previous = recordContent(r.RRInfo)
	}
	content, err := dnsutil.MXValue(desired.Type, desired.Content, desired.Priority, previous)
	if err != nil {
		return "", err
	}
	value, priority, weight, port, err := parseContent(desired.Type, content)
	if err != nil {
		return "", err
	}
	typ := desired.Type
	switch typ {
	case "REDIRECT_URL":
		typ = "EXPLICIT_URL"
	case "FORWARD_URL":
		typ = "IMPLICIT_URL"
	}
	// MX/SRV parameters belong to the new RDATA. Load-balancing weight
	// belongs to the original routing policy and must survive a conversion.
	if currentWeight := r.routingWeight(); currentWeight != nil {
		switch typ {
		case "A", "AAAA", "CNAME", "JNAME":
			weight = currentWeight
		default:
			return "", dns.ErrInvalidDNSRequest
		}
	}
	r.HostRecord, r.Type = host, typ
	return p.update(ctx, zone, prior.ID, z, r, value, desired.TTL, priority, weight, port)
}
