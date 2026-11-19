package namesilo

import (
	"context"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/dnsdrivers/registrarutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func (p *provider) RecordEditCapabilities() dns.RecordEditCapabilities {
	// dnsUpdateRecord accepts rrhost and rrdistance. The provider assigns a fresh ID on success.
	return dns.RecordEditCapabilities{Rename: true, Priority: true}
}

func (p *provider) ReplaceDNSRecord(ctx context.Context, zone string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", err
	}
	row, err := p.record(ctx, z, prior.ID)
	if err != nil {
		return "", err
	}
	current, err := row.view()
	if err != nil {
		return "", err
	}
	_, value, err := registrarutil.EditValue("namesilo", z, p.RecordEditCapabilities(), prior, current, desired)
	if err != nil {
		return "", err
	}
	q, err := recordParams(z, desired.Name, row.Type, value, desired.TTL)
	if err != nil {
		return "", err
	}
	q.Set("rrid", prior.ID)
	return p.write(ctx, "dnsUpdateRecord", q)
}
