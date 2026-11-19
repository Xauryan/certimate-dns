package aliyunwaf

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/pkg/core"
)

type testLegacyRPC func(*http.Request) (*http.Response, error)

func (f testLegacyRPC) Call(r *http.Request, _ *http.Transport) (*http.Response, error) { return f(r) }

type testLegacyCAS struct {
	core.Certmgr
	calls int
}

func (m *testLegacyCAS) Upload(context.Context, string, string) (*core.CertmgrUploadResult, error) {
	m.calls++
	return &core.CertmgrUploadResult{CertId: "9007199254740993"}, nil
}

func TestWAF2RegionalBindings(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"example.test", "*.example.test"}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	for _, tc := range []struct {
		name, region, instance, domains, group string
		badAck                                 bool
		wantBinds                              []string
		wantUpload                             bool
		wantError                              bool
	}{
		{"discover instance and replace multi-domain cert", "cn-hangzhou", "", "Example.TEST, example.test\n*.example.test", "selected", false, []string{"example.test", "*.example.test"}, true, false},
		{"use specified international instance", "ap-southeast-1", "waf-v2", "www.example.test", "selected", false, []string{"www.example.test"}, true, false},
		{"reject unrelated instance", "cn-hangzhou", "unrelated", "example.test", "selected", false, nil, false, true},
		{"reject wrong resource group", "cn-hangzhou", "", "example.test", "other", false, nil, false, true},
		{"reject missing domain with no writes", "cn-hangzhou", "", "", "selected", false, nil, false, true},
		{"reject mismatched cert before writes", "cn-hangzhou", "", "unrelated.test", "selected", false, nil, false, true},
		{"reject wrong acknowledgement", "cn-hangzhou", "", "example.test", "selected", true, []string{"example.test"}, true, true},
		{"reject unknown region", "bogus", "", "example.test", "selected", false, nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &DeployerConfig{AccessKeyId: "synthetic-id", AccessKeySecret: "synthetic-secret", ResourceGroupId: "selected", ServiceVersion: "2.0", Region: tc.region, Domain: tc.domains, InstanceId: tc.instance}
			deployer, err := NewDeployer(cfg)
			if err != nil {
				t.Fatal(err)
			}
			cas := &testLegacyCAS{}
			deployer.sdkCertmgr = cas
			var bound []string
			deployer.sdkClient.HttpClient = testLegacyRPC(func(r *http.Request) (*http.Response, error) {
				q := r.URL.Query()
				if tc.region == "bogus" || r.URL.Host != "wafopenapi."+tc.region+".aliyuncs.com" || q.Get("Version") != "2019-09-10" || q.Get("Signature") == "" || q.Get("SignatureMethod") != "HMAC-SHA1" {
					t.Fatal("unexpected endpoint, version or signature")
				}
				body := ""
				switch q.Get("Action") {
				case "DescribeInstanceInfo":
					if q.Get("ResourceGroupId") != "selected" || q.Get("InstanceId") != tc.instance {
						t.Fatal("invalid instance filter")
					}
					body = `{"InstanceInfo":{"InstanceId":"waf-v2","Status":1}}`
				case "DescribeDomain":
					if q.Get("InstanceId") != "waf-v2" || q.Get("Domain") == "" {
						t.Fatal("invalid protected domain filter")
					}
					body = fmt.Sprintf(`{"Domain":{"ResourceGroupId":%q}}`, tc.group)
				case "CreateCertificateByCertificateId":
					if r.Method != http.MethodPost || q.Get("InstanceId") != "waf-v2" || q.Get("CertificateId") != "9007199254740993" || q.Has("PrivateKey") {
						t.Fatal("invalid WAF 2.0 bind")
					}
					bound = append(bound, q.Get("Domain"))
					body = `{"CertificateId":9007199254740993,"RequestId":"accepted"}`
					if tc.badAck {
						body = `{"CertificateId":42}`
					}
				default:
					t.Fatal("unexpected legacy action")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			_, err = deployer.Deploy(context.Background(), certPEM, keyPEM)
			if (err != nil) != tc.wantError || (cas.calls == 1) != tc.wantUpload || !slices.Equal(bound, tc.wantBinds) {
				t.Fatalf("upload count %d bound %v error %v", cas.calls, bound, err)
			}
		})
	}
}
