package tencentcloudssldeploy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/certimate-go/certimate/pkg/core"
)

func TestSignedLighthouseAndCloudBaseDeployments(t *testing.T) {
	cert, key := domainCertificate(t)
	cfg := DomainDeployerConfig{SecretId: "fixture-id", SecretKey: "fixture-secret", ProjectId: 17, Region: "ap-shanghai", Domain: "site.example.test"}
	for _, product := range []struct {
		name, resourceID, instance, detail string
		create                             func(DomainDeployerConfig, string) (core.Deployer, error)
	}{
		{"lighthouse", "lhins-fixture", "ap-shanghai|lhins-fixture|site.example.test", `"InstanceId":"lhins-fixture"`, NewLighthouseDeployer},
		{"tcb", "env-fixture", "AccessService|ap-shanghai|env-fixture|site.example.test", `"EnvId":"env-fixture","TCBType":"AccessService","Region":"ap-shanghai"`, NewCloudBaseDeployer},
	} {
		t.Run(product.name, func(t *testing.T) {
			if _, err := product.create(cfg, product.resourceID+"|unused"); err == nil {
				t.Fatal("accepted additional resource components")
			}
			for _, correctTarget := range []bool{true, false} {
				p, err := product.create(cfg, product.resourceID)
				if err != nil {
					t.Fatal(err)
				}
				d := p.(*domainDeployer)
				d.sdkCertmgr = &fakeInventory{}
				actions := 0
				d.sdkClient.WithHttpTransport(roundTrip(func(r *http.Request) (*http.Response, error) {
					actions++
					if !strings.Contains(r.Header.Get("Authorization"), "TC3-HMAC-SHA256 Credential=fixture-id/") ||
						r.Header.Get("X-TC-Region") != cfg.Region || r.URL.Host != "ssl.tencentcloudapi.com" {
						t.Error("missing signed region and SSL endpoint")
					}
					var req struct {
						InstanceIdList []string
						CertificateId  string
						ResourceType   string
						DeployRecordId string
					}
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						return nil, err
					}
					var reply string
					switch r.Header.Get("X-TC-Action") {
					case "DeployCertificateInstance":
						if req.CertificateId != "test-cert" || req.ResourceType != product.name || len(req.InstanceIdList) != 1 || req.InstanceIdList[0] != product.instance {
							t.Error("did not select the requested binding")
						}
						reply = `{"DeployRecordId":27,"DeployStatus":1}`
					case "DescribeHostDeployRecordDetail":
						if req.DeployRecordId != "27" {
							t.Error("did not poll the submitted record")
						}
						host := cfg.Domain
						if !correctTarget {
							host = "wrong.example.test"
						}
						reply = `{"TotalCount":1,"SuccessTotalCount":1,"DeployRecordDetailList":[{"CertId":"test-cert","Domains":["` + host + `"],"Status":1,` + product.detail + `}]}`
					default:
						t.Error("unexpected API action")
					}
					return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"Response":` + reply + `}`))}, nil
				}))
				if _, err := d.Deploy(t.Context(), cert, "invalid-key"); err == nil || actions != 0 || d.sdkCertmgr.(*fakeInventory).uploads != 0 {
					t.Fatal("invalid certificate material reached Tencent Cloud")
				}
				if _, err := d.Deploy(t.Context(), cert, key); (err == nil) != correctTarget || actions != 2 {
					t.Fatalf("unexpected confirmation, correctTarget=%v calls=%d err=%v", correctTarget, actions, err)
				}
			}
		})
	}
}

func domainCertificate(t *testing.T) (certificate, key string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"site.example.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}
