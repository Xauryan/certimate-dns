package dnsmanagement

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
)

func TestCloudDNSProvidersUseAccountTransport(t *testing.T) {
	for _, tc := range []struct{ provider, endpoint string }{
		{"aliyun", "alidns.aliyuncs.com"},
		{"aliyunesa", "esa.cn-hangzhou.aliyuncs.com"},
		{"tencentcloud", "dnspod.tencentcloudapi.com"},
		{"tencenteo", "teo.intl.tencentcloudapi.com"},
		{"baiducloud", "dns.baidubce.com"},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			calls := 0
			tr := &http.Transport{Proxy: func(r *http.Request) (*url.URL, error) {
				calls++
				if r.URL.Scheme != "https" || r.URL.Host != tc.endpoint {
					t.Error("unexpected signed request destination")
				}
				// Return before dialing so this checks SDK routing without an upstream service.
				return nil, errors.New("synthetic route selection diagnostic")
			}}
			account := &domain.Access{Provider: tc.provider, Config: map[string]any{"accessKeyId": "sample-id", "accessKeySecret": "sample-key", "secretAccessKey": "sample-key", "secretId": "sample-id", "secretKey": "sample-key", "siteType": "intl"}, DNSManagementTransport: tr}
			p, err := Open(account, true)
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.Zones(t.Context(), 1)
			if calls == 0 || err == nil || strings.Contains(err.Error(), "synthetic route selection") {
				t.Fatal("missing routed DNS call or unredacted transport error")
			}
		})
	}
}
