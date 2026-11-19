package henet

import (
	"context"
	"reflect"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

var _ dns.RecordEditor = (*provider)(nil)

func (p *provider) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true}
}

func (p *provider) ReplaceDNSRecord(ctx context.Context, zone string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	if _, err := dnsutil.PositiveID(prior.ID); err != nil {
		return "", err
	}
	if !editable(desired.Type) || desired.TTL < 300 || desired.Content == "" || desired.Weight != nil || desired.Description != "" {
		return "", dns.ErrInvalidDNSRequest
	}
	if (desired.Type == "MX") != (desired.Priority != nil) || (desired.Priority != nil && (*desired.Priority < 0 || *desired.Priority > 65535)) {
		return "", dns.ErrInvalidDNSRequest
	}
	c, z, rows, err := p.records(ctx, zone)
	if err != nil {
		return "", err
	}
	host, err := dnsutil.RelativeName(desired.Name, z.Name)
	if err != nil {
		return "", err
	}
	name := dnsutil.FullName(host, z.Name)
	values := form(z, prior.ID, name, desired.Type, desired.Content, desired.TTL, desired.Priority)
	desired.Content = values.Get("Content")
	found := false
	for _, r := range rows {
		if r.ID == prior.ID {
			if err := dnsutil.CheckReplacement("henet", prior, r, desired); err != nil {
				return "", dns.ErrInvalidDNSRequest
			}
			found = true
		}
		if dnsutil.RecordDestinationConflict(r, prior.ID, name, desired) {
			return "", dns.ErrInvalidDNSRequest
		}
	}
	if !found {
		return "", domain.ErrRecordNotFound
	}
	values.Set("hosted_dns_editrecord", "Update")
	doc, err := p.mutate(ctx, c, values, "Successfully updated record")
	if err != nil {
		return "", err
	}
	updated, err := parseRecords(doc, z)
	if err != nil {
		return "", err
	}
	for _, r := range updated {
		if r.ID != prior.ID {
			continue
		}
		if r.Name != name || r.Type != desired.Type || r.TTL != desired.TTL || r.Status != prior.Status || !reflect.DeepEqual(r.Priority, desired.Priority) || !dnsutil.EqualRecordValue(r.Type, r.Content, desired.Content) {
			return "", failure
		}
		return r.ID, nil
	}
	return "", failure
}
