package selfhostutil_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsmgr"
	"github.com/certimate-go/certimate/internal/dnsdrivers/goedge"
	"github.com/certimate-go/certimate/internal/dnsdrivers/powerdns"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestAccountProxySurvivesTLSOptions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		new    func(*domain.Access) (dns.Provider, error)
		config map[string]any
	}{
		{"dnsmgr", dnsmgr.New, map[string]any{"uid": "12", "apiKey": "synthetic"}},
		{"powerdns", powerdns.New, map[string]any{"apiKey": "synthetic", "allowInsecureConnections": true}},
		{"goedge", goedge.New, map[string]any{"apiRole": "user", "accessKeyId": "test-id", "accessKey": "synthetic", "nsClusterId": 12, "allowInsecureConnections": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Any direct request reaches this local origin and fails the test.
			direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("bypassed account proxy"); w.WriteHeader(502) }))
			defer direct.Close()
			hits := 0
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits++
				if !r.URL.IsAbs() {
					t.Error("not an HTTP proxy request")
				}
				switch r.URL.Path {
				case "/api/domain":
					fmt.Fprint(w, `{"total":0,"rows":[]}`)
				case "/api/v1/servers/localhost/zones":
					fmt.Fprint(w, `[]`)
				case "/APIAccessTokenService/getAPIAccessToken":
					fmt.Fprint(w, `{"code":200,"data":{"token":"synthetic-token","expiresAt":"4294967295"}}`)
				case "/NSDomainService/countAllNSDomains":
					fmt.Fprint(w, `{"code":200,"data":{"count":0}}`)
				case "/NSDomainService/listNSDomains":
					fmt.Fprint(w, `{"code":200,"data":{"nsDomains":[]}}`)
				default:
					t.Error("unexpected path")
					w.WriteHeader(404)
				}
			}))
			defer proxy.Close()
			proxyURL, _ := url.Parse(proxy.URL)
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
			tc.config["serverUrl"] = direct.URL
			api, err := tc.new(&domain.Access{Config: tc.config, DNSManagementTransport: transport})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = api.Zones(context.Background(), 1); err != nil {
				t.Fatal(err)
			}
			if hits == 0 || transport.TLSClientConfig.InsecureSkipVerify {
				t.Error("failed to preserve account transport isolation")
			}
		})
	}
}
