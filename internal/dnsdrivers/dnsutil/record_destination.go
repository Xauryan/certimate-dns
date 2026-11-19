package dnsutil

import (
	"net/netip"
	"reflect"
	"strings"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func equalTarget(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// EqualRecordValue compares the editable value as it appears in provider responses.
func EqualRecordValue(typ, a, b string) bool {
	switch typ {
	case "CNAME", "DNAME", "ALIAS", "ANAME", "NS", "PTR", "MX":
		return equalTarget(a, b)
	case "A", "AAAA":
		aa, err := netip.ParseAddr(a)
		bb, e := netip.ParseAddr(b)
		if err == nil && e == nil {
			return aa == bb
		}
	case "SRV":
		left, right := strings.Fields(a), strings.Fields(b)
		return len(left) == 4 && len(right) == 4 && reflect.DeepEqual(left[:3], right[:3]) && equalTarget(left[3], right[3])
	}
	return a == b
}

// RecordDestinationConflict checks sibling entries before a native single-record
// change. A CNAME can coexist with DNSSEC signatures and denial-of-existence data.
func RecordDestinationConflict(row dns.DNSRecord, id, name string, desired dns.RecordInput) bool {
	if row.ID == id || !equalTarget(row.Name, name) {
		return false
	}
	if row.Type == "RRSIG" || row.Type == "NSEC" {
		return false
	}
	if row.Type == "CNAME" || desired.Type == "CNAME" {
		return true
	}
	if row.Type != desired.Type {
		return false
	}
	switch desired.Type {
	case "APP", "DNAME", "ALIAS":
		return true
	case "MX":
		if !reflect.DeepEqual(row.Priority, desired.Priority) {
			return false
		}
	}
	return EqualRecordValue(row.Type, row.Content, desired.Content)
}
