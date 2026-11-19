// Package dnscheck verifies public DNS answers for records within a selected zone.
package dnscheck

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/miekg/dns"
)

type Result struct {
	Status   string   `json:"status"`
	Expected string   `json:"expected,omitempty"`
	Actual   []string `json:"actual"`
}

var ErrInvalid = errors.New("invalid propagation check")
var ErrResolver = errors.New("DNS resolver did not return a complete answer")

var types = []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "CAA", "PTR", "LOC"}

func Check(ctx context.Context, zone, fqdn, recordType, expected string) (Result, error) {
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return Result{}, ErrResolver
	}
	addresses := make([]string, 0, len(config.Servers))
	for _, server := range config.Servers {
		addresses = append(addresses, net.JoinHostPort(server, config.Port))
	}
	return check(ctx, zone, fqdn, recordType, expected, addresses)
}

func check(ctx context.Context, zone, fqdn, recordType, expected string, addresses []string) (Result, error) {
	fqdn = dns.Fqdn(strings.ToLower(fqdn))
	origin := dns.Fqdn(strings.ToLower(zone))
	typ := strings.ToUpper(recordType)
	if _, ok := dns.IsDomainName(fqdn); !ok || strings.ContainsAny(fqdn, "\\;()@\"") || strings.IndexFunc(fqdn, unicode.IsSpace) >= 0 ||
		origin == "." || !dns.IsSubDomain(origin, fqdn) || !slices.Contains(types, typ) || expected == "" || len(expected) > 65535 {
		return Result{}, ErrInvalid
	}
	request := new(dns.Msg)
	request.SetQuestion(fqdn, dns.StringToType[typ])
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	for _, address := range addresses {
		udp := dns.Client{Net: "udp", Timeout: 2 * time.Second}
		reply, _, err := udp.ExchangeContext(ctx, request, address)
		if err == nil && reply.Truncated {
			tcp := dns.Client{Net: "tcp", Timeout: 2 * time.Second}
			reply, _, err = tcp.ExchangeContext(ctx, request, address)
		}
		if err != nil || reply == nil || reply.Truncated || len(reply.Question) != 1 || !strings.EqualFold(reply.Question[0].Name, fqdn) ||
			reply.Question[0].Qtype != request.Question[0].Qtype {
			continue
		}
		if reply.Rcode == dns.RcodeNameError {
			return Result{Status: "not_found", Actual: []string{}}, nil
		}
		if reply.Rcode != dns.RcodeSuccess {
			continue
		}
		actual := []string{}
		var active bool
		for _, rr := range reply.Answer {
			h := rr.Header()
			if h.Class != dns.ClassINET || h.Rrtype != request.Question[0].Qtype || !strings.EqualFold(h.Name, fqdn) {
				continue
			}
			value := recordValue(rr)
			actual = append(actual, value)
			if sameValue(typ, expected, value) {
				active = true
			}
		}
		if len(actual) == 0 {
			return Result{Status: "not_found", Actual: actual}, nil
		}
		if active {
			return Result{Status: "active", Actual: actual}, nil
		}
		return Result{Status: "mismatch", Actual: actual, Expected: expected}, nil
	}
	return Result{}, ErrResolver
}

func recordValue(rr dns.RR) string {
	switch r := rr.(type) {
	case *dns.A:
		return r.A.String()
	case *dns.AAAA:
		return r.AAAA.String()
	case *dns.CNAME:
		return strings.TrimSuffix(r.Target, ".")
	case *dns.MX:
		return strings.TrimSuffix(r.Mx, ".")
	case *dns.NS:
		return strings.TrimSuffix(r.Ns, ".")
	case *dns.PTR:
		return strings.TrimSuffix(r.Ptr, ".")
	case *dns.TXT:
		return strings.Join(r.Txt, "")
	default:
		return strings.TrimPrefix(rr.String(), rr.Header().String())
	}
}

func sameValue(typ, want, got string) bool {
	switch typ {
	case "A", "AAAA":
		left, lerr := netip.ParseAddr(want)
		right, rerr := netip.ParseAddr(got)
		return lerr == nil && rerr == nil && left == right
	case "CNAME", "MX", "NS", "PTR":
		return strings.EqualFold(strings.TrimSuffix(want, "."), strings.TrimSuffix(got, "."))
	default:
		return want == got
	}
}
