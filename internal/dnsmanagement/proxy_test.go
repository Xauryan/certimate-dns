package dnsmanagement

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
)

func TestProxyPolicyIsAccountScopedAndDoesNotSerializeTheEndpoint(t *testing.T) {
	endpoint, _ := url.Parse("http://operator:synthetic-secret@127.0.0.1:8080")
	loads := 0
	loader := func() (*url.URL, error) { loads++; return endpoint, nil }
	access := &domain.Access{Config: map[string]any{}}
	inherit, err := accountTransport(access, loader)
	if err != nil || inherit.DNSManagementTransport != nil || loads != 0 {
		t.Fatal("existing account did not retain inherited routing")
	}
	access.Config["dnsManagementProxy"] = false
	direct, err := accountTransport(access, loader)
	if err != nil || direct.DNSManagementTransport == nil || direct.DNSManagementTransport.Proxy != nil || loads != 0 {
		t.Fatal("explicit direct routing loaded proxy settings")
	}
	access.Config["dnsManagementProxy"] = true
	forced, err := accountTransport(access, loader)
	if err != nil || loads != 1 {
		t.Fatal("missing proxy transport")
	}
	got, err := forced.DNSManagementTransport.Proxy(&http.Request{})
	if err != nil || got.String() != endpoint.String() {
		t.Fatal("incorrect selected route")
	}
	if access.DNSManagementTransport != nil || direct.DNSManagementTransport.Proxy != nil {
		t.Fatal("shared account or another route mutated")
	}
	data, err := json.Marshal(forced)
	if err != nil || strings.Contains(string(data), "secret") || strings.Contains(string(data), "127.0.0.1") {
		t.Fatal("serialized routing credentials")
	}
	if _, err = accountTransport(access, func() (*url.URL, error) { return nil, errors.New("synthetic-secret") }); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("missing safe proxy failure")
	}
	if _, err = Open(access, false); err == nil {
		t.Fatal("forced proxy opened without instance settings")
	}
	access.Config["dnsManagementProxy"] = "true"
	if _, err = accountTransport(access, loader); err == nil || loads != 1 {
		t.Fatal("invalid account flag accepted or used")
	}
}
