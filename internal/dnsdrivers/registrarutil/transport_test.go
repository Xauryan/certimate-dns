package registrarutil_test

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsla"
	"github.com/certimate-go/certimate/internal/dnsdrivers/dynv6"
	"github.com/certimate-go/certimate/internal/dnsdrivers/namesilo"
	"github.com/certimate-go/certimate/internal/dnsdrivers/spaceship"
	"github.com/certimate-go/certimate/internal/dnsdrivers/west"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAccountTransportUsedForInventoryAndGuardedWrites(t *testing.T) {
	fallback := http.DefaultTransport
	http.DefaultTransport = roundTrip(func(*http.Request) (*http.Response, error) {
		t.Error("account transport bypassed")
		return nil, errors.New("network disabled")
	})
	t.Cleanup(func() { http.DefaultTransport = fallback })
	cases := []struct {
		name, host, zone string
		config           map[string]any
		newProvider      func(*domain.Access) (dns.Provider, error)
	}{
		{"DNS.LA", "api.dns.la", "1", map[string]any{"apiId": "sample", "apiSecret": "sample"}, dnsla.New},
		{"dynv6", "dynv6.com", "example.test", map[string]any{"httpToken": "sample"}, dynv6.New},
		{"NameSilo", "www.namesilo.com", "example.test", map[string]any{"apiKey": "sample"}, namesilo.New},
		{"Spaceship", "spaceship.dev", "example.test", map[string]any{"apiKey": "sample", "apiSecret": "sample"}, spaceship.New},
		{"West", "api.west.cn", "example.test", map[string]any{"username": "sample", "apiPassword": "sample"}, west.New},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			calls := 0
			transport := &http.Transport{}
			transport.RegisterProtocol("https", roundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Host != c.host {
					t.Errorf("wrong provider host %s", r.URL.Host)
				}
				if _, ok := r.Context().Deadline(); !ok {
					t.Error("missing client timeout")
				}
				// Simulate a failed inventory or ownership read before any mutation.
				return &http.Response{Request: r, StatusCode: 503, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("synthetic-provider-diagnostic"))}, nil
			}))
			p, err := c.newProvider(&domain.Access{Config: c.config, DNSManagementTransport: transport})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.Zones(t.Context(), 1); err == nil || strings.Contains(err.Error(), "synthetic-provider-diagnostic") {
				t.Fatal("invalid inventory failure")
			}
			if _, err := p.DeleteDNSRecord(t.Context(), c.zone, "7"); err == nil || strings.Contains(err.Error(), "synthetic-provider-diagnostic") {
				t.Fatal("invalid guarded deletion failure")
			}
			if calls != 2 {
				t.Fatalf("expected 2 account transport requests, got %d", calls)
			}
		})
	}
}
