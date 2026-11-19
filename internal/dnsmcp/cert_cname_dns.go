package dnsmcp

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func publishedCname(ctx context.Context, name, target string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(config.Servers) == 0 {
		cname, err := net.DefaultResolver.LookupCNAME(ctx, dns.Fqdn(name))
		var dnserr *net.DNSError
		if errors.As(err, &dnserr) && dnserr.IsNotFound {
			return false, nil
		}
		return strings.EqualFold(cname, dns.Fqdn(target)), err
	}
	var lastErr error
	for _, server := range config.Servers {
		found, err := publishedCnameAt(ctx, net.JoinHostPort(server, config.Port), name, target)
		if err == nil {
			return found, nil
		}
		lastErr = err
	}
	return false, lastErr
}

// Query the CNAME itself. The delegation destination may have no address
// records, and may have no TXT record between ACME authorizations.
func publishedCnameAt(ctx context.Context, server, name, target string) (bool, error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeCNAME)
	client := &dns.Client{Timeout: 2 * time.Second}
	msg, _, err := client.ExchangeContext(ctx, q, server)
	if err == nil && msg.Truncated {
		client.Net = "tcp"
		msg, _, err = client.ExchangeContext(ctx, q, server)
	}
	if err != nil {
		return false, err
	}
	// A CNAME can point at a name which currently has no RRsets. Some
	// resolvers return the CNAME along with NXDOMAIN for the target.
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return false, errors.New("DNS resolver returned an unsuccessful response")
	}
	for _, rr := range msg.Answer {
		cname, ok := rr.(*dns.CNAME)
		if ok && cname.Hdr.Class == dns.ClassINET && strings.EqualFold(cname.Hdr.Name, q.Question[0].Name) &&
			strings.EqualFold(cname.Target, dns.Fqdn(target)) {
			return true, nil
		}
	}
	return false, nil
}
