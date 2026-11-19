package dnsmanagement

import (
	"net/url"

	"github.com/certimate-go/certimate/internal/dnsproxysettings"
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/pkg/utils/http/dnsproxy"
	"github.com/pocketbase/pocketbase/core"
)

// WithAccountTransport creates an ephemeral credential view. The stored account
// carries only a routing preference, never proxy credentials or an endpoint.
func WithAccountTransport(app core.App, a *domain.Access) (*domain.Access, error) {
	return accountTransport(a, func() (*url.URL, error) {
		if app == nil {
			return nil, domain.NewError(400, "DNS proxy is not configured")
		}
		return dnsproxysettings.LoadURL(app)
	})
}

func accountTransport(a *domain.Access, load func() (*url.URL, error)) (*domain.Access, error) {
	if a == nil {
		return nil, domain.ErrInvalidParams
	}
	raw, exists := a.Config["dnsManagementProxy"]
	if !exists {
		return a, nil
	} // Existing accounts use the deployment's environment routing.
	use, ok := raw.(bool)
	if !ok {
		return nil, domain.ErrInvalidParams
	}
	var endpoint *url.URL
	if use {
		var err error
		endpoint, err = load()
		if err != nil || endpoint == nil {
			return nil, domain.NewError(400, "DNS proxy is not configured")
		}
	}
	tr, err := dnsproxy.NewTransport(endpoint)
	if err != nil {
		return nil, domain.NewError(400, "invalid DNS proxy configuration")
	}
	account := *a
	account.DNSManagementTransport = tr
	return &account, nil
}
