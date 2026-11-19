package dnsutil

import (
	"reflect"
	"slices"
	"strings"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

// CheckReplacement rejects stale snapshots and changes to attributes that have
// their own provider operations. RecordEditor changes only record data and identity.
func CheckReplacement(provider string, prior, current dns.DNSRecord, desired dns.RecordInput) error {
	caps, ok := dns.ProviderCapabilities(provider)
	if !ok || !caps.AllowsTTL(desired.TTL) || !caps.AllowsType(desired.Type) || strings.TrimSpace(desired.Content) == "" {
		return dns.ErrInvalidDNSRequest
	}
	if desired.Priority != nil && (*desired.Priority < 0 || *desired.Priority > 65535 || !slices.Contains(caps.PriorityTypes, desired.Type)) {
		return dns.ErrInvalidDNSRequest
	}
	if current.ID == "" || current.ReadOnly || !reflect.DeepEqual(prior, current) || desired.Line != current.Line || desired.Description != current.Description || !reflect.DeepEqual(desired.Weight, current.Weight) {
		return dns.ErrInvalidDNSRequest
	}
	return nil
}
