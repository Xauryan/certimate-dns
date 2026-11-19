package west

import (
	"context"
	"strconv"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/dnsdrivers/registrarutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func (p *provider) RecordEditCapabilities() dns.RecordEditCapabilities {
	// moddnsrecord identifies the existing owner by ID and can change the record type.
	return dns.RecordEditCapabilities{Retype: true, Priority: true}
}

func (p *provider) ReplaceDNSRecord(ctx context.Context, zone string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", err
	}
	row, err := p.find(ctx, z, prior.ID)
	if err != nil {
		return "", err
	}
	current, err := row.view(z)
	if err != nil {
		return "", err
	}
	_, content, err := registrarutil.EditValue("westcn", z, p.RecordEditCapabilities(), prior, current, desired)
	if err != nil {
		return "", err
	}
	form := updateForm(z, row)
	form.Set("type", desired.Type)
	form.Set("value", content)
	form.Set("ttl", strconv.Itoa(desired.TTL))
	if desired.Type != row.Type {
		form.Del("level")
	}
	if err := setValue(form, desired.Type, content, desired.TTL); err != nil {
		return "", err
	}
	if err := p.call(ctx, form, nil); err != nil {
		return "", err
	}
	return prior.ID, nil
}
