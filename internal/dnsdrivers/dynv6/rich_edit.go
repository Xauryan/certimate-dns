package dynv6

import (
	"context"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/dnsdrivers/registrarutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func (p *provider) RecordEditCapabilities() dns.RecordEditCapabilities {
	// The OpenAPI update schema exposes the record name, data and priority. Type belongs to the creation schema.
	return dns.RecordEditCapabilities{Rename: true, Priority: true}
}

func (p *provider) ReplaceDNSRecord(ctx context.Context, zone string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", err
	}
	path, row, err := p.record(ctx, z, prior.ID)
	if err != nil {
		return "", err
	}
	current, err := recordView(*row, z)
	if err != nil {
		return "", err
	}
	host, content, err := registrarutil.EditValue("dynv6", z, p.RecordEditCapabilities(), prior, current, desired)
	if err != nil {
		return "", err
	}
	req, err := recordValue(desired.Type, content)
	if err != nil {
		return "", err
	}
	if host == "@" {
		host = z
	}
	req.Name = &host
	if err := p.api.JSON(ctx, "PATCH", path, req, nil); err != nil {
		return "", err
	}
	return prior.ID, nil
}
