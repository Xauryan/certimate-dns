package dnsmgr

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	u "github.com/certimate-go/certimate/internal/dnsdrivers/selfhostutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type mutationID u.Text

func (p *provider) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true}
}

func (p *provider) ZoneRecordEditCapabilities(ctx context.Context, zid string) (dns.RecordEditCapabilities, error) {
	z, err := p.zone(ctx, zid)
	return z.editCapabilities(), err
}

func (z zone) editCapabilities() dns.RecordEditCapabilities {
	if z.Config.RecordEdit != nil {
		return *z.Config.RecordEdit
	}
	if z.Config.NativeRecords {
		return dns.RecordEditCapabilities{}
	}
	// The PHP endpoint acknowledges an edit without returning a record ID.
	// Only delegate to drivers whose update preserves the original ID.
	switch z.Config.Type {
	case "aliyun", "bt", "cloudflare", "dnspod", "goedge":
		return dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true}
	}
	return dns.RecordEditCapabilities{}
}

func (p *provider) ReplaceDNSRecord(ctx context.Context, zid string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	defer u.LockZone(p.client.Base, zid)()
	z, err := p.zone(ctx, zid)
	if err != nil {
		return "", err
	}
	caps := z.editCapabilities()
	if caps == (dns.RecordEditCapabilities{}) {
		return "", dns.ErrInvalidDNSRequest
	}
	row, err := p.oldInZone(ctx, z, prior.ID)
	if err != nil {
		return "", err
	}
	current, err := row.dns(z)
	if err != nil {
		return "", err
	}
	host, err := u.ReplacementHost("dnsmgr", z.Name, prior, current, desired)
	if err != nil {
		return "", err
	}
	if !caps.Rename && u.Full(host, z.Name) != u.Name(current.Name) || !caps.Retype && desired.Type != current.Type {
		return "", dns.ErrInvalidDNSRequest
	}
	if z.Config.RecordEdit == nil {
		switch z.Config.Type {
		case "cloudflare":
			if row.Status == "0" || current.Proxied && desired.Type != "A" && desired.Type != "AAAA" && desired.Type != "CNAME" {
				return "", dns.ErrInvalidDNSRequest
			}
		case "aliyun", "dnspod":
			if current.Weight != nil && *current.Weight > 0 && current.Type != desired.Type {
				return "", dns.ErrInvalidDNSRequest
			}
		case "bt":
			if current.Weight != nil && desired.Type == "MX" {
				return "", dns.ErrInvalidDNSRequest
			}
			if current.Type == "MX" && desired.Type != "MX" {
				row.Weight = "" // The PHP adapter will apply its normal default weight.
			}
		}
	}
	row.Name, row.Type, row.Value, row.TTL, row.MX = host, desired.Type, desired.Content, u.Text(strconv.Itoa(desired.TTL)), ""
	if desired.Type == "MX" {
		fallback := 1
		if current.Type == "MX" {
			if current.Priority == nil {
				return "", dns.ErrInvalidDNSRequest
			}
			fallback = *current.Priority
		}
		target, preference, err := dnsutil.MXParts(desired.Content, desired.Priority, fallback, 65535)
		if err != nil || !caps.Priority && current.Type == "MX" && preference != fallback {
			return "", dns.ErrInvalidDNSRequest
		}
		row.Value, row.MX = target, u.Text(strconv.Itoa(preference))
	}
	form := row.updateForm()
	if z.Config.NativeRecords {
		if p.signatureMode != "v2" {
			return "", dns.ErrInvalidDNSRequest
		}
		snapshot, err := json.Marshal(current)
		if err != nil {
			return "", u.ErrProvider
		}
		form.Set("expected", string(snapshot))
		form.Del("line")
		form.Del("remark")
		form.Del("weight")
	}
	path := "record/update/" + zid
	if z.Config.RecordEdit != nil || z.Config.NativeRecords {
		var finalID mutationID
		if err = p.post(ctx, path, form, &finalID); err != nil {
			return "", err
		}
		if finalID == "" {
			return "", u.ErrProvider
		}
		return string(finalID), nil
	}
	if err = p.post(ctx, path, form, nil); err != nil {
		return "", err
	}
	return prior.ID, nil
}
