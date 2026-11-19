package qingcloud

import (
	"context"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/dnsdrivers/selfhostutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func (p *provider) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true}
}

// ReplaceDNSRecord updates the existing RouteWize record by ID. Owner name, TTL,
// type, view and mode are RRset properties, so one value cannot change them for
// its siblings. MX priority is stored per value.
func (p *provider) ReplaceDNSRecord(ctx context.Context, zone string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", err
	}
	rel, err := dnsutil.RelativeName(desired.Name, z)
	if err != nil {
		return "", err
	}
	rid, vid, err := parseID(prior.ID)
	if err != nil {
		return "", err
	}
	defer selfhostutil.LockZone("qingcloud", z)()
	s, err := p.selectValue(ctx, z, rid, vid)
	if err != nil {
		return "", err
	}
	g := s.Groups[s.groupIndex]
	old := g.Values[s.valueIndex]
	found, err := row(s.record, g, old)
	if err != nil {
		return "", err
	}
	if err = dnsutil.CheckReplacement("qingcloud", prior, found, desired); err != nil {
		return "", err
	}
	name := dnsutil.FullName(rel, z)
	identity := !strings.EqualFold(name, found.Name) || desired.Type != found.Type
	if identity || desired.TTL != s.TTL {
		if len(s.Groups) != 1 || len(g.Values) != 1 {
			return "", dns.ErrInvalidDNSRequest
		}
	}
	if desired.Type != s.Type && s.Mode != 1 {
		return "", dns.ErrInvalidDNSRequest
	}
	if desired.Priority != nil && desired.Type != "MX" {
		return "", dns.ErrInvalidDNSRequest
	}
	next, err := wireValue(desired.Type, desired.Content, desired.Priority)
	if err != nil {
		return "", err
	}
	if identity {
		// An existing target set would have to be merged. Refuse rather than
		// changing its policy, TTL or group membership.
		records, err := p.searchRecords(ctx, z, name)
		if err != nil {
			return "", err
		}
		for _, r := range records {
			if strings.EqualFold(r.Name, name) && r.Type == desired.Type && r.Line == found.Line && r.ID != prior.ID {
				return "", dns.ErrInvalidDNSRequest
			}
		}
	}
	s.Name = name
	s.Type = desired.Type
	s.TTL = desired.TTL
	return p.replaceSelection(ctx, z, s, next, false)
}
