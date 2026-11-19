package dnscatalog

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Some ccTLDs publish registration dates only over WHOIS. Resolve their
// port-43 service through the IANA HTTPS gateway, then query that host only.
var registryWhoisLine = regexp.MustCompile(`(?mi)^\s*whois:[ \t]*([a-z0-9-]+(?:\.[a-z0-9-]+)+)[ \t]*\r?$`)

type dialWhois func(context.Context, string, string) (net.Conn, error)

func (r *registry) whois(ctx context.Context, registered string, dial dialWhois) (string, string, error) {
	tld := registered[strings.LastIndexByte(registered, '.')+1:]
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.iana.org/whois?q="+url.QueryEscape(tld), nil)
	if err != nil {
		return "", "", unavailable
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return "", "", unavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", "", unavailable
	}
	source, err := io.ReadAll(io.LimitReader(resp.Body, 128<<10))
	if err != nil {
		return "", "", unavailable
	}
	match := registryWhoisLine.FindSubmatch(source)
	if match == nil {
		return "", "", unavailable
	}
	conn, err := dial(ctx, "tcp", net.JoinHostPort(string(match[1]), "43"))
	if err != nil {
		return "", "", unavailable
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err = conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return "", "", unavailable
	}
	if _, err = io.WriteString(conn, registered+"\r\n"); err != nil {
		return "", "", unavailable
	}
	data, err := io.ReadAll(io.LimitReader(conn, 256<<10))
	if err != nil {
		return "", "", unavailable
	}
	created, expires := "", ""
	domainMatched := false
	for line := range strings.SplitSeq(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "domain", "domain name", "domain name (utf-8)":
			if strings.EqualFold(value, registered) {
				domainMatched = true
			}
		case "creation date", "registration time", "created", "created on", "registered on":
			created = whoisDate(value)
		case "registry expiry date", "expiration date", "expiration time", "expires", "expiry date", "paid-till":
			expires = whoisDate(value)
		}
	}
	if !domainMatched || expires == "" {
		return "", "", unavailable
	}
	return created, expires, nil
}

func whoisDate(value string) string {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", time.DateOnly, "02-Jan-2006", "2006.01.02"} {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC().Format(time.DateOnly)
		}
	}
	return ""
}
