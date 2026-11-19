// Package dnsmanagement adapts cloud DNS APIs to Certimate's account and record model.
package dnsmanagement

import (
	"errors"
	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func ptr[T any](v T) *T { return &v }
func val[T any](p *T) (v T) {
	if p != nil {
		return *p
	}
	return
}
func zoneName(s string) (string, error)          { return dnsutil.ZoneName(s) }
func relative(name, zone string) (string, error) { return dnsutil.RelativeName(name, zone) }
func fullName(label, zone string) string         { return dnsutil.FullName(label, zone) }
func intPtr[T ~int32 | ~int64 | ~uint64](v *T) *int {
	if v == nil {
		return nil
	}
	n := int(*v)
	return &n
}
func providerError(provider string) error {
	return errors.New(provider + " DNS request failed; refresh before retrying a change")
}
func accountField(a *domain.Access, key string) string { return dnsutil.Field(a, key) }
func newPage[T any](page, total int) *dns.DNSPage[T] {
	return &dns.DNSPage[T]{Items: []T{}, Info: dns.PageInfo{Page: page, Total: total}}
}
