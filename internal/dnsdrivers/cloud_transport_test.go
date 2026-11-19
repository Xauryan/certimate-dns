package dnsdrivers_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certimate-go/certimate/internal/dnsdrivers/aws"
	"github.com/certimate-go/certimate/internal/dnsdrivers/huawei"
	"github.com/certimate-go/certimate/internal/dnsdrivers/huoshan"
	"github.com/certimate-go/certimate/internal/dnsdrivers/jdcloud"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestSignedCloudRequestsUseTheAccountProxy(t *testing.T) {
	// Catch regressions without allowing a fallback request out of the test.
	original := http.DefaultTransport
	http.DefaultTransport = &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		t.Error("attempted provider request on the default transport")
		return nil, errors.New("direct connection disabled")
	}}
	t.Cleanup(func() { http.DefaultTransport = original })

	var metadataRequests atomic.Int32
	metadata := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadataRequests.Add(1)
		if r.URL.Path == "/latest/api/token" && r.Method == "PUT" {
			w.Header().Set("X-aws-ec2-metadata-token-ttl-seconds", "300")
			fmt.Fprint(w, "test-token")
			return
		}
		if r.Header.Get("X-aws-ec2-metadata-token") != "test-token" {
			t.Error("metadata read omitted IMDSv2 token")
		}
		switch r.URL.Path {
		case "/latest/meta-data/iam/security-credentials/":
			fmt.Fprint(w, "test-role")
		case "/latest/meta-data/iam/security-credentials/test-role":
			fmt.Fprintf(w, `{"Code":"Success","AccessKeyId":"test-id","SecretAccessKey":"test-key","Token":"test-session","Expiration":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		default:
			t.Errorf("unexpected metadata path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer metadata.Close()
	t.Setenv("AWS_EC2_METADATA_DISABLED", "false")
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", metadata.URL)

	for _, test := range []struct {
		name, host   string
		makeProvider func(*domain.Access) (dns.Provider, error)
		imds         bool
	}{
		{"aws", "route53.amazonaws.com", aws.New, false},
		{"aws-imds", "route53.amazonaws.com", aws.New, true},
		{"huawei", "dns.myhuaweicloud.com", huawei.New, false},
		{"volcengine", "dns.volcengineapi.com", huoshan.New, false},
		{"jdcloud", "domainservice.jdcloud-api.com", jdcloud.New, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var connections atomic.Int32
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				connections.Add(1)
				if r.Method != "CONNECT" || r.Host != net.JoinHostPort(test.host, "443") {
					t.Errorf("unexpected proxied request %s %s", r.Method, r.Host)
				}
				http.Error(w, "synthetic-proxy-message", http.StatusBadGateway)
			}))
			defer proxy.Close()
			proxyURL, err := url.Parse(proxy.URL)
			if err != nil {
				t.Fatal(err)
			}
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if addr != proxyURL.Host {
					t.Error("attempted to bypass proxy")
					return nil, errors.New("invalid destination")
				}
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			}}
			defer transport.CloseIdleConnections()
			config := map[string]any{"accessKeyId": "test-id", "secretAccessKey": "test-key", "accessKeySecret": "test-key"}
			if test.imds {
				config = map[string]any{"authMethod": "imds"}
			}
			p, err := test.makeProvider(&domain.Access{Config: config, DNSManagementTransport: transport})
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.Zones(t.Context(), 1)
			if err == nil || strings.Contains(err.Error(), "synthetic-proxy-message") {
				t.Errorf("unexpected error %v", err)
			}
			if n := connections.Load(); n != 1 {
				t.Fatalf("DNS API proxy connections %d, want 1", n)
			}
		})
	}
	if n := metadataRequests.Load(); n != 3 {
		t.Errorf("direct IMDS calls %d, want token, role name and credentials", n)
	}
}
