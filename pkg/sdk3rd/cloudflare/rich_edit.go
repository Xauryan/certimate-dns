package cloudflare

import (
	"context"
	"net/http"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

var _ dns.RecordEditor = (*Client)(nil)

func (*Client) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true}
}

func (c *Client) ReplaceDNSRecord(ctx context.Context, zone string, prior DNSRecord, desired RecordInput) (string, error) {
	cap, _ := dns.ProviderCapabilities("cloudflare")
	if !dnsID.MatchString(zone) || !dnsID.MatchString(prior.ID) || prior.ReadOnly || desired.Content == "" || !cap.AllowsType(desired.Type) || !cap.AllowsTTL(desired.TTL) {
		return "", ErrInvalidDNSRequest
	}
	path := "/zones/" + zone + "/dns_records/" + prior.ID
	row, err := dnsRequest[wireRecord](ctx, c, http.MethodGet, path, nil, nil)
	if err != nil {
		return "", err
	}
	old := row.Result.record()
	if old.ID != prior.ID || old.Name == "" || old.Type == "" {
		return "", ErrInvalidDNSRequest
	}
	if err := dnsutil.CheckReplacement("cloudflare", prior, old, desired); err != nil {
		return "", err
	}
	if old.Proxied && desired.Type != "A" && desired.Type != "AAAA" && desired.Type != "CNAME" {
		return "", ErrInvalidDNSRequest
	}

	// Resolve the selected zone before sending a rename. DNS-only tokens may lack
	// zone read permission, so same-owner edits use the scoped record detail.
	name := old.Name
	if !strings.EqualFold(strings.TrimSuffix(desired.Name, "."), strings.TrimSuffix(old.Name, ".")) {
		z := row.Result.ZoneName
		if z == "" {
			d, err := c.ZoneDetails(ctx, zone)
			if err != nil {
				return "", err
			}
			z = d.Name
		}
		before, err := dnsutil.RelativeName(old.Name, z)
		if err != nil {
			return "", err
		}
		after, err := dnsutil.RelativeName(desired.Name, z)
		if err != nil {
			return "", err
		}
		if strings.HasSuffix(before, "_pause") != strings.HasSuffix(after, "_pause") {
			return "", ErrInvalidDNSRequest
		}
		name = dnsutil.FullName(after, z)
	}
	content := desired.Content
	priority := desired.Priority
	if old.Type == "MX" || old.Type == "URI" {
		if old.Priority == nil || prior.Priority == nil || *old.Priority != *prior.Priority {
			return "", ErrInvalidDNSRequest
		}
		if priority == nil && old.Type == desired.Type {
			priority = old.Priority
		}
	}
	if desired.Type == "MX" {
		fallback := 1
		var p int
		content, p, err = dnsutil.MXParts(content, priority, fallback, 65535)
		if err != nil {
			return "", err
		}
		priority = &p
	} else if priority != nil && desired.Type != "URI" {
		return "", ErrInvalidDNSRequest
	}
	body, err := cloudflareContent(desired.Type, content, priority)
	if err != nil {
		return "", err
	}
	body["name"] = name
	body["type"] = desired.Type
	body["ttl"] = desired.TTL
	// PATCH preserves provider-only metadata, tags, comments and the proxy flag.
	return writeRecord(ctx, c, http.MethodPatch, path, body)
}
