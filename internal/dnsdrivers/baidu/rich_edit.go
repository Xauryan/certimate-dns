package baidu

import (
	"context"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func (p *provider) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true}
}

func (r record) view(fqdn string) dns.DNSRecord {
	return dns.DNSRecord{ID: r.ID, Name: fqdn, Type: r.Type, Content: r.Value, TTL: r.TTL, Line: r.Line, Status: r.Status, Description: r.Description, Priority: r.Priority}
}

func (p *provider) ReplaceDNSRecord(ctx context.Context, zone string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	z, row, err := p.current(ctx, zone, prior.ID)
	if err != nil {
		return "", err
	}
	current := row.view(dnsutil.FullName(row.Rr, z))
	if err := dnsutil.CheckReplacement("baiducloud", prior, current, desired); err != nil {
		return "", err
	}
	host, err := dnsutil.RelativeName(desired.Name, z)
	if err != nil {
		return "", err
	}
	if (current.Type == "NS" && strings.EqualFold(current.Name, z)) || (desired.Type == "NS" && host == "@") {
		return "", dns.ErrInvalidDNSRequest
	}
	row.Value = desired.Content
	switch desired.Type {
	case "MX":
		preference := 1
		if row.Type == "MX" {
			if row.Priority == nil {
				return "", failure
			}
			preference = *row.Priority
		}
		value, priority, err := dnsutil.MXParts(desired.Content, desired.Priority, preference, 50)
		if err != nil {
			return "", err
		}
		row.Value, row.Priority = value, &priority
	default:
		if desired.Priority != nil {
			return "", dns.ErrInvalidDNSRequest
		}
		row.Priority = nil
	}
	// The record ID selects one row. Baidu's update accepts rr and type
	// alongside TTL, value, description and MX priority; line and status stay
	// on the original record and are not writable through this endpoint.
	row.Rr, row.Type, row.TTL = host, desired.Type, desired.TTL
	if err := p.update(ctx, z, *row); err != nil {
		return "", err
	}
	return row.ID, nil
}
