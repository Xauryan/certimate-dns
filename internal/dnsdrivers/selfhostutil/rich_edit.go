package selfhostutil

import (
	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

// ReplacementHost checks the observed record against the fresh provider read and
// returns the validated relative owner name for the replacement.
func ReplacementHost(provider, zone string, prior, current dns.DNSRecord, desired dns.RecordInput) (string, error) {
	if prior.ID == "" || prior.Type == "SOA" || prior.Type == "NS" && Name(prior.Name) == Name(zone) {
		return "", dns.ErrInvalidDNSRequest
	}
	if err := dnsutil.CheckReplacement(provider, prior, current, desired); err != nil {
		return "", err
	}
	host, err := dnsutil.RelativeName(desired.Name, zone)
	if err != nil || host == "@" && desired.Type == "NS" {
		return "", dns.ErrInvalidDNSRequest
	}
	return host, nil
}
