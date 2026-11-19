package goedge

import (
	"context"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	u "github.com/certimate-go/certimate/internal/dnsdrivers/selfhostutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func (r *nsRecord) dns(zone string) dns.DNSRecord {
	return dns.DNSRecord{ID: r.ID.String(), Type: r.Type, Name: dnsutil.FullName(r.Name, zone), Content: r.content(), Weight: &r.Weight, Priority: r.priority(), Description: r.Description, TTL: r.TTL, Line: strings.Join(r.codes(), ","), Status: r.status()}
}
func (p *provider) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true}
}
func (p *provider) ReplaceDNSRecord(ctx context.Context, zid string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	defer u.LockZone(p.rpc.Base, zid)()
	n, err := dnsutil.PositiveID(prior.ID)
	if err != nil {
		return "", err
	}
	z, err := p.zone(ctx, zid)
	if err != nil {
		return "", err
	}
	row, err := p.recordInZone(ctx, z, prior.ID, n)
	if err != nil {
		return "", err
	}
	host, err := u.ReplacementHost("goedge", z.Name, prior, row.dns(z.Name), desired)
	if err != nil {
		return "", err
	}
	fallback := 1
	if row.Type == "MX" {
		fallback = row.MXPriority
	}
	if row.Type != desired.Type {
		row.recordData = recordData{Description: row.Description, Weight: row.Weight}
	}
	row.Name, row.Type, row.TTL = host, desired.Type, desired.TTL
	value := desired.Content
	if desired.Type == "MX" {
		value, row.MXPriority, err = dnsutil.MXParts(value, desired.Priority, fallback, 65535)
		if err != nil {
			return "", err
		}
	}
	if err = row.setContent(value); err != nil {
		return "", err
	}
	if err = p.update(ctx, row); err != nil {
		return "", err
	}
	return prior.ID, nil
}
