package dnsla

import (
	"context"

	"github.com/certimate-go/certimate/internal/dnsdrivers/registrarutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func (p *provider) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true}
}

func (p *provider) ReplaceDNSRecord(ctx context.Context, zoneID string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	z, err := p.zone(ctx, zoneID)
	if err != nil {
		return "", err
	}
	row, err := p.findInZone(ctx, z, prior.ID)
	if err != nil {
		return "", err
	}
	host, value, err := registrarutil.EditValue("dnsla", z.name(), p.RecordEditCapabilities(), prior, row.view(z), desired)
	if err != nil {
		return "", err
	}
	if desired.Type != row.kind() {
		if err := row.setType(desired.Type); err != nil {
			return "", err
		}
	}
	row.Host, row.TTL, row.DomainID = host, desired.TTL, ""
	if err := row.setContent(value); err != nil {
		return "", err
	}
	if err := p.call(ctx, "PUT", "/api/record", nil, row, nil); err != nil {
		return "", err
	}
	return prior.ID, nil
}
