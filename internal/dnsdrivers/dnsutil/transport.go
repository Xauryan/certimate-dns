package dnsutil

import (
	"net/http"

	"github.com/certimate-go/certimate/internal/domain"
)

// HTTPClientFor uses the server-selected account route without changing global transports.
func HTTPClientFor(a *domain.Access) *http.Client {
	c := NewHTTPClient()
	if a != nil && a.DNSManagementTransport != nil {
		c.Transport = a.DNSManagementTransport
	}
	return c
}

// TransportFor also supports SDKs that accept only a RoundTripper.
func TransportFor(a *domain.Access) http.RoundTripper {
	if a != nil && a.DNSManagementTransport != nil {
		return a.DNSManagementTransport
	}
	return http.DefaultTransport
}
