package dnsmanagement

import "testing"

func TestProviderCapabilitiesCoverAllRegisteredAccounts(t *testing.T) {
	for _, id := range SupportedProviders() {
		c, ok := ProviderCapabilities(id)
		if !ok || !c.AllowsType("A") || !c.AllowsTTL(c.DefaultTTL) || c.AllowsTTL(-1) {
			t.Errorf("%s: invalid descriptor", id)
		}
		for _, kind := range c.PriorityTypes {
			if !c.AllowsType(kind) {
				t.Errorf("%s: unsupported priority type %s", id, kind)
			}
		}
	}
	for id := range providerCapabilities {
		if !IsSupportedProvider(id) {
			t.Errorf("orphaned descriptor for %s", id)
		}
	}
	c, _ := ProviderCapabilities("cloudflare")
	c.Types[0] = "invalid"
	c, _ = ProviderCapabilities("cloudflare")
	if !c.AllowsType("A") {
		t.Fatal("shared mutable descriptor")
	}
	if _, ok := ProviderCapabilities("unknown"); ok {
		t.Fatal("unknown adapter accepted")
	}
}
