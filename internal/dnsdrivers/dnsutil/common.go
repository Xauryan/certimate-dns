// Package dnsutil holds wire-independent naming and pagination rules for DNS providers.
package dnsutil

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	"golang.org/x/net/idna"
)

func Field(a *domain.Access, key string) string {
	if a == nil {
		return ""
	}
	value, _ := a.Config[key].(string)
	return value
}

func ZoneName(raw string) (string, error) {
	name, err := idna.Lookup.ToASCII(strings.TrimSuffix(raw, "."))
	if err != nil || len(name) > 253 {
		return "", dns.ErrInvalidDNSRequest
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return "", dns.ErrInvalidDNSRequest
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return "", dns.ErrInvalidDNSRequest
			}
		}
	}
	return strings.ToLower(name), nil
}

func RelativeName(raw, zone string) (string, error) {
	z, err := ZoneName(zone)
	if err != nil {
		return "", err
	}
	if raw == "@" {
		return "@", nil
	}
	raw = strings.TrimSuffix(raw, ".")
	labels := strings.Split(raw, ".")
	for i, label := range labels {
		if i == 0 && label == "*" {
			continue
		}
		// Underscores are significant in challenge and service labels.
		parts := strings.Split(label, "_")
		for j, part := range parts {
			if part == "" {
				continue
			}
			s, err := idna.Lookup.ToASCII(part)
			if err != nil || strings.Contains(s, ".") {
				return "", dns.ErrInvalidDNSRequest
			}
			parts[j] = strings.ToLower(s)
		}
		labels[i] = strings.Join(parts, "_")
		if labels[i] == "" || len(labels[i]) > 63 {
			return "", dns.ErrInvalidDNSRequest
		}
	}
	name := strings.Join(labels, ".")
	if len(name) > 253 {
		return "", dns.ErrInvalidDNSRequest
	}
	if name == z {
		return "@", nil
	}
	if label, ok := strings.CutSuffix(name, "."+z); ok {
		return label, nil
	}
	return "", dns.ErrInvalidDNSRequest
}

func FullName(host, zone string) string {
	zone = strings.TrimSuffix(zone, ".")
	if host == "@" || host == "" {
		return zone
	}
	return host + "." + zone
}

func Page[T any](page, total int) *dns.DNSPage[T] {
	return &dns.DNSPage[T]{Items: []T{}, Info: dns.PageInfo{Page: page, Total: total}}
}

func ValidPage(page int) bool { return page >= 1 && page <= 10000000 }

func SlicePage[T any](items []T, page int) (*dns.DNSPage[T], error) {
	if !ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	out := Page[T](page, len(items))
	start := (page - 1) * dns.DNSPageSize
	if start < len(items) {
		out.Items = items[start:min(start+dns.DNSPageSize, len(items))]
	}
	return out, nil
}

// PositiveID accepts the canonical decimal identifier used by path-based APIs.
func PositiveID(id string) (int64, error) {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n < 1 || strconv.FormatInt(n, 10) != id {
		return 0, dns.ErrInvalidDNSRequest
	}
	return n, nil
}

func NewHTTPClient() *http.Client {
	return &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}

// ReadResponse bounds memory and discards provider error bodies and transport URLs.
func ReadResponse(c *http.Client, req *http.Request) ([]byte, error) {
	resp, err := c.Do(req)
	if err != nil {
		if req.Context().Err() != nil {
			return nil, req.Context().Err()
		}
		return nil, errors.New("DNS provider request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New("DNS provider returned HTTP " + strconv.Itoa(resp.StatusCode))
	}
	const limit = 8 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || len(body) > limit {
		return nil, errors.New("invalid DNS provider response")
	}
	return body, nil
}
