package dnsutil

import (
	"strconv"
	"strings"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

// MXPriority extracts a single MX preference from zone-file presentation.
func MXPriority(kind, content string) *int {
	if kind != "MX" {
		return nil
	}
	fields := strings.Fields(content)
	if len(fields) != 2 {
		return nil
	}
	n, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		return nil
	}
	preference := int(n)
	return &preference
}

// MXParts decodes separate editor fields or complete MX RDATA into the
// exchange and preference expected by providers with structured APIs.
func MXParts(content string, priority *int, fallback, maximum int) (string, int, error) {
	fields := strings.Fields(content)
	preference := fallback
	switch len(fields) {
	case 1:
		if priority != nil {
			preference = *priority
		}
	case 2:
		n, err := strconv.ParseUint(fields[0], 10, 16)
		if err != nil || priority != nil && *priority != int(n) {
			return "", 0, dns.ErrInvalidDNSRequest
		}
		preference = int(n)
	default:
		return "", 0, dns.ErrInvalidDNSRequest
	}
	if preference < 0 || preference > maximum {
		return "", 0, dns.ErrInvalidDNSRequest
	}
	return fields[len(fields)-1], preference, nil
}

// MXValue accepts complete RDATA or a bare exchange from the record editor.
// A bare exchange keeps the existing preference on update.
func MXValue(kind, content string, priority *int, previous string) (string, error) {
	if kind != "MX" {
		if priority != nil {
			return "", dns.ErrInvalidDNSRequest
		}
		return content, nil
	}
	fallback := 1
	if previous != "" && priority == nil && len(strings.Fields(content)) == 1 {
		stored := MXPriority(kind, previous)
		if stored == nil {
			return "", dns.ErrInvalidDNSRequest
		}
		fallback = *stored
	}
	target, preference, err := MXParts(content, priority, fallback, 65535)
	if err != nil {
		return "", err
	}
	return strconv.Itoa(preference) + " " + target, nil
}
