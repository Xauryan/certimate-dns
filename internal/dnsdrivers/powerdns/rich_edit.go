package powerdns

import (
	"context"
	"slices"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	u "github.com/certimate-go/certimate/internal/dnsdrivers/selfhostutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func (p *provider) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true}
}
func (p *provider) ReplaceDNSRecord(ctx context.Context, zid string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	defer u.LockZone(p.client.Base, zid)()
	z, err := p.zone(ctx, zid)
	if err != nil {
		return "", err
	}
	src, old, err := z.find(prior.ID)
	if err != nil {
		return "", err
	}
	host, err := u.ReplacementHost("powerdns", z.Name, prior, src.row(zid, old), desired)
	if err != nil {
		return "", err
	}
	name := u.Full(host, z.Name) + "."
	previous := ""
	if src.Type == "MX" {
		previous = old.Content
	}
	raw, err := dnsutil.MXValue(desired.Type, desired.Content, desired.Priority, previous)
	if err != nil {
		return "", err
	}
	raw, err = content(desired.Type, raw)
	if err != nil {
		return "", err
	}
	next := record{Content: raw, Disabled: old.Disabled}
	if strings.EqualFold(src.Name, name) && src.Type == desired.Type {
		if len(src.Records) > 1 && src.TTL != desired.TTL {
			return "", dns.ErrInvalidDNSRequest
		}
		for i, r := range src.Records {
			if r == old {
				src.Records[i] = next
			} else if r.Content == next.Content {
				return "", dns.ErrInvalidDNSRequest
			}
		}
		src.TTL = desired.TTL
		if err = p.replace(ctx, z, src); err != nil {
			return "", err
		}
		return src.row(zid, next).ID, nil
	}
	// Both record sets are replaced in one zone PATCH. Preserve shared TTLs and
	// comments on the source, and refuse to overwrite either at the destination.
	dst := rrset{Name: name, Type: desired.Type, TTL: desired.TTL, Change: "REPLACE", Comments: src.Comments}
	for _, s := range z.RRSets {
		if !strings.EqualFold(s.Name, name) || s.Type != desired.Type {
			continue
		}
		if s.TTL != desired.TTL || !slices.Equal(s.Comments, src.Comments) {
			return "", dns.ErrInvalidDNSRequest
		}
		dst.Comments = nil // Keep the existing destination comments.
		for _, r := range s.Records {
			if r.Content == next.Content {
				return "", dns.ErrInvalidDNSRequest
			}
		}
		dst.Records = s.Records
		break
	}
	dst.Records = append(dst.Records, next)
	src.Records = slices.DeleteFunc(src.Records, func(r record) bool { return r == old })
	src.Change = "REPLACE"
	src.Comments = nil
	if err = p.write(ctx, z, src, dst); err != nil {
		return "", err
	}
	return dst.row(zid, next).ID, nil
}
