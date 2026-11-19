package technitium

import (
	"context"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

var _ dns.RecordEditor = (*provider)(nil)

func (p *provider) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true, Priority: true}
}

func (p *provider) ReplaceDNSRecord(ctx context.Context, zone string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	// The API updates exactly one DNS type and has no replacement-type argument.
	if desired.Type != prior.Type || desired.TTL < 1 || desired.Content == "" || desired.Weight != nil {
		return "", dns.ErrInvalidDNSRequest
	}
	if (desired.Type == "MX") != (desired.Priority != nil) || (desired.Priority != nil && (*desired.Priority < 0 || *desired.Priority > 65535)) {
		return "", dns.ErrInvalidDNSRequest
	}
	z, rows, err := p.records(ctx, zone)
	if err != nil {
		return "", err
	}
	host, err := dnsutil.RelativeName(desired.Name, z.Name)
	if err != nil {
		return "", err
	}
	name := dnsutil.FullName(host, z.Name)
	var current *record
	for i := range rows {
		if rows[i].ID == prior.ID {
			if err := dnsutil.CheckReplacement("technitiumdns", prior, rows[i].DNSRecord, desired); err != nil {
				return "", dns.ErrInvalidDNSRequest
			}
			current = &rows[i]
		}
		if dnsutil.RecordDestinationConflict(rows[i].DNSRecord, prior.ID, name, desired) {
			return "", dns.ErrInvalidDNSRequest
		}
	}
	if current == nil {
		return "", domain.ErrRecordNotFound
	}
	return p.updateFields(ctx, z.Name, *current, name, desired.Content, desired.Priority, desired.TTL, current.Status == "disabled", current.Description)
}
