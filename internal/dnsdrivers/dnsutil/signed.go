package dnsutil

import (
	"errors"
	"net/http"

	"github.com/certimate-go/certimate/internal/domain"
)

// AlibabaHTTPClient adapts the management client's timeout, proxy and redirect
// policy to the transport hook used by the Alibaba Cloud SDK.
type AlibabaHTTPClient struct{ Client *http.Client }

func (c AlibabaHTTPClient) Call(req *http.Request, _ *http.Transport) (*http.Response, error) {
	return c.Client.Do(req)
}

type signedTransport struct {
	host string
	next http.RoundTripper
}

// SignedTransportFor keeps Tencent SDK requests on the selected HTTPS endpoint.
// The SDK owns its http.Client and follows redirects, so stop a redirect here,
// before another request can carry signed headers to a new destination.
func SignedTransportFor(a *domain.Access, host string) http.RoundTripper {
	return signedTransport{host: host, next: TransportFor(a)}
}

func (t signedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != t.host || r.URL.User != nil {
		return nil, errors.New("invalid DNS service endpoint")
	}
	resp, err := t.next.RoundTrip(r)
	if err == nil && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		resp.Body.Close()
		return nil, errors.New("DNS service returned a redirect")
	}
	return resp, err
}
