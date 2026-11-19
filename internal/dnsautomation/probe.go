package dnsautomation

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func validProtocol(m Monitor) bool {
	return (m.Protocol == "ping" && m.Port == 0) || (m.Protocol == "http" && m.Port == 80) || (m.Protocol == "https" && m.Port == 443) || (m.Protocol == "tcp" && (m.Port == 80 || m.Port == 443))
}

var excludedNetworks = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range strings.Fields("0.0.0.0/8 168.63.129.16/32 100.64.0.0/10 169.254.0.0/16 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 240.0.0.0/4 2001::/23 2001:db8::/32 2002::/16 3fff::/20") {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func allowedProbeIP(s string) bool {
	ip, err := netip.ParseAddr(s)
	if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.Is4In6() || ip.Zone() != "" {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, block := range excludedNetworks {
		if block.Contains(ip) {
			return false
		}
	}
	return true
}

// The operator controls the probe destinations independently of the DNS admin.
// Only explicitly listed public endpoint IPs are eligible (no hostnames or CIDR).
func authorizedProbe(value string) bool {
	ip, err := netip.ParseAddr(value)
	if err != nil || !allowedProbeIP(value) {
		return false
	}
	for _, part := range strings.Split(os.Getenv("CERTIMATE_DNS_PROBE_IPS"), ",") {
		allowed, e := netip.ParseAddr(strings.TrimSpace(part))
		if e == nil && ip == allowed {
			return true
		}
	}
	return false
}

// Dial only the public address read from the managed primary record at activation.
// Host and TLS SNI use the authorized DNS record name. No proxy, lookup or redirect.
func probe(ctx context.Context, d Definition) (bool, error) {
	m := d.Monitor
	if !authorizedProbe(d.probeOrigin()) || !validProtocol(m) || !fqdn(d.Target.Name) {
		return false, errInput
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(m.Timeout)*time.Second)
	defer cancel()
	if m.Protocol == "ping" {
		// One ICMP echo to the same allowlisted literal used by all probes.
		args := []string{"-n", "-c", "1", d.probeOrigin()}
		if runtime.GOOS == "windows" {
			args = []string{"-n", "1", "-w", strconv.Itoa(m.Timeout * 1000), d.probeOrigin()}
		}
		err := exec.CommandContext(ctx, "ping", args...).Run()
		if err == nil {
			return true, nil
		}
		if ctx.Err() == context.DeadlineExceeded {
			return false, nil
		}
		var result *exec.ExitError
		if errors.As(err, &result) && result.ExitCode() == 1 {
			return false, nil
		}
		return false, errProvider
	}
	addr := net.JoinHostPort(d.probeOrigin(), strconv.Itoa(m.Port))
	dialer := net.Dialer{}
	if m.Protocol == "tcp" {
		c, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return false, nil
		}
		c.Close()
		return true, nil
	}
	name := strings.TrimSuffix(d.Target.Name, ".")
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name},
		DisableKeepAlives: true, MaxResponseHeaderBytes: 16384,
	}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.Protocol+"://"+name+"/", nil)
	if err != nil {
		return false, errInput
	}
	response, err := client.Do(req)
	if err != nil {
		return false, nil
	}
	response.Body.Close()
	return response.StatusCode >= 200 && response.StatusCode < 400, nil
}
