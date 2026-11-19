package bt

import (
	"context"
	"strconv"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	u "github.com/certimate-go/certimate/internal/dnsdrivers/selfhostutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func (r record) dns(name string) dns.DNSRecord {
	status := "enabled"
	if r.State == 1 {
		status = "disabled"
	}
	var priority, weight *int
	if r.Type == "MX" {
		priority = &r.MX
	} else if r.MX > 1 {
		weight = &r.MX
	}
	return dns.DNSRecord{ID: strconv.FormatInt(r.ID, 10), Type: r.Type, Name: dnsutil.FullName(r.Host, name), Content: r.Value, TTL: r.TTL, Line: strconv.FormatInt(r.ViewID, 10), Status: status, Description: r.Remark, Weight: weight, Priority: priority}
}

func (p *provider) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true}
}
func (p *provider) ReplaceDNSRecord(ctx context.Context, zid string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	defer u.LockZone(endpoint, zid)()
	row, err := p.old(ctx, zid, prior.ID)
	if err != nil {
		return "", err
	}
	name, err := p.zoneName(ctx, row.zoneKey)
	if err != nil {
		return "", err
	}
	host, err := u.ReplacementHost("bt", name, prior, row.dns(name), desired)
	if err != nil {
		return "", err
	}
	fields := row.zoneKey.params()
	fields["record_id"], fields["record"], fields["type"], fields["value"], fields["ttl"] = row.ID, host, desired.Type, desired.Content, desired.TTL
	fields["view_id"], fields["remark"], fields["mx"] = row.ViewID, row.Remark, row.MX
	// Baota stores MX preference and routing weight in the same field.
	// A non-default policy cannot survive conversion to MX.
	if desired.Type == "MX" {
		fallback := 1
		if row.Type == "MX" {
			fallback = row.MX
		} else if prior.Weight != nil {
			return "", dns.ErrInvalidDNSRequest
		}
		exchange, priority, err := dnsutil.MXParts(desired.Content, desired.Priority, fallback, 65535)
		if err != nil {
			return "", err
		}
		fields["value"], fields["mx"] = exchange, priority
	} else if row.Type == "MX" {
		fields["mx"] = 1
	}
	if err = p.post(ctx, "/record/update", fields, nil); err != nil {
		return "", err
	}
	return prior.ID, nil
}
