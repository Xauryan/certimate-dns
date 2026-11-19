package tencenteo

import (
	"context"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func (p *provider) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true}
}

func (p *provider) ReplaceDNSRecord(ctx context.Context, zone string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	z, err := p.zone(ctx, zone)
	if err != nil {
		return "", err
	}
	row, err := p.recordInZone(ctx, z, prior.ID)
	if err != nil {
		return "", err
	}
	current := recordView(row)
	if err := dnsutil.CheckReplacement("tencenteo", prior, current, desired); err != nil {
		return "", err
	}
	name, err := ownerName(desired.Name, z.Name)
	if err != nil {
		return "", err
	}
	if (current.Type == "NS" && strings.EqualFold(current.Name, z.Name)) || (desired.Type == "NS" && name == z.Name) {
		return "", dns.ErrInvalidDNSRequest
	}
	switch desired.Type {
	case "A", "AAAA", "CNAME":
	default:
		// Changing type must not silently drop a traffic weight or geographic route.
		if current.Weight != nil || (val(row.Location) != "" && !strings.EqualFold(*row.Location, "Default")) {
			return "", dns.ErrInvalidDNSRequest
		}
		row.Weight, row.Location = nil, nil
	}
	content := desired.Content
	if desired.Type == "MX" {
		fallback := 0
		if current.Priority != nil {
			fallback = *current.Priority
		}
		value, priority, err := dnsutil.MXParts(content, desired.Priority, fallback, 50)
		if err != nil {
			return "", err
		}
		content, row.Priority = value, ptr(int64(priority))
	} else {
		if desired.Priority != nil {
			return "", dns.ErrInvalidDNSRequest
		}
		row.Priority = nil
	}
	row.Name, row.Type, row.Content, row.TTL = &name, &desired.Type, &content, ptr(int64(desired.TTL))
	if err := p.modify(ctx, zone, row); err != nil {
		return "", err
	}
	return *row.RecordId, nil
}
