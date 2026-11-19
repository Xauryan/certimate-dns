package registrarutil

import (
	"reflect"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

// EditValue compares the freshly fetched provider row with the record the caller
// was authorized to edit. Metadata changes are handled by separate operations.
func EditValue(provider, zone string, caps dns.RecordEditCapabilities, prior, current dns.DNSRecord, desired dns.RecordInput) (host, content string, err error) {
	if current.ReadOnly || current.ID == "" || !reflect.DeepEqual(prior, current) {
		return "", "", domain.NewError(409, "DNS record changed; refresh before editing")
	}
	available, ok := dns.ProviderCapabilities(provider)
	if !ok || !available.AllowsType(desired.Type) || !available.AllowsTTL(desired.TTL) || desired.Content == "" ||
		desired.Line != current.Line || desired.Description != current.Description || !reflect.DeepEqual(desired.Weight, current.Weight) {
		return "", "", dns.ErrInvalidDNSRequest
	}
	host, err = dnsutil.RelativeName(desired.Name, zone)
	if err != nil {
		return "", "", err
	}
	oldHost, err := dnsutil.RelativeName(current.Name, zone)
	if err != nil || host != oldHost && !caps.Rename || desired.Type != current.Type && !caps.Retype {
		return "", "", dns.ErrInvalidDNSRequest
	}
	previous := ""
	if current.Type == desired.Type {
		previous = current.Content
	}
	content, err = dnsutil.MXValue(desired.Type, desired.Content, desired.Priority, previous)
	return host, content, err
}
