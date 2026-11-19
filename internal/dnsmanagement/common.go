// Package dnsmanagement adapts cloud DNS APIs to Certimate's account and record model.
package dnsmanagement

import (
	"errors"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	"golang.org/x/net/idna"
	"strings"
)

func ptr[T any](v T) *T { return &v }
func val[T any](p *T) (v T) {
	if p != nil {
		return *p
	}
	return
}
func zoneName(s string) (string, error) {
	n, err := idna.Lookup.ToASCII(strings.ToLower(strings.TrimSuffix(s, ".")))
	if err != nil || n == "" || len(n) > 253 || strings.ContainsAny(n, "*/:@") {
		return "", dns.ErrInvalidDNSRequest
	}
	for _, label := range strings.Split(n, ".") {
		if label == "" || len(label) > 63 {
			return "", dns.ErrInvalidDNSRequest
		}
	}
	return n, nil
}
func relative(name, zone string) (string, error) {
	if name == "@" {
		return "@", nil
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == zone {
		return "@", nil
	}
	label, ok := strings.CutSuffix(name, "."+zone)
	if !ok || label == "" || strings.HasPrefix(label, ".") || strings.Contains(label, "..") {
		return "", dns.ErrInvalidDNSRequest
	}
	return label, nil
}
func fullName(label, zone string) string {
	if label == "@" || label == "" {
		return zone
	}
	return label + "." + zone
}
func providerError(provider string) error {
	return errors.New(provider + " DNS request failed; refresh before retrying a change")
}
func accountField(a *domain.Access, key string) string { s, _ := a.Config[key].(string); return s }
func newPage[T any](page, total int) *dns.DNSPage[T] {
	return &dns.DNSPage[T]{Items: []T{}, Info: dns.PageInfo{Page: page, Total: total}}
}
