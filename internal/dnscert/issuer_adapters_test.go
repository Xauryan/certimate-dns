package dnscert

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
)

// Both vendor SDKs use their ordinary serializers and signers. The transport
// supplies provider responses in memory, including ambiguous and stale replies.
type issuerTransport func(*http.Request) (*http.Response, error)

func (f issuerTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func (f issuerTransport) Call(r *http.Request, _ *http.Transport) (*http.Response, error) {
	return f(r)
}

func issuerJSON(payload string) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(payload))}
}

func TestAliyunSelectAndSubmit(t *testing.T) {
	ctx := context.Background()
	issuer, err := newAliyun(&domain.Access{Config: map[string]any{"accessKeyId": "synthetic-id", "accessKeySecret": "synthetic-secret", "resourceGroupId": "rg-selected"}})
	if err != nil {
		t.Fatal(err)
	}
	p := issuer.(*aliyunIssuer)
	req := OrderRequest{Domain: "www.example.test", Algorithm: "RSA3072", ContactID: "123"}
	var actions []string
	p.client.HttpClient = issuerTransport(func(r *http.Request) (*http.Response, error) {
		q := r.URL.Query()
		action := strings.Join(r.Header["x-acs-action"], "")
		actions = append(actions, action)
		switch action {
		case "ListInstances":
			if q.Get("ShowSize") != "100" || q.Get("Status") != "inactive" || q.Get("ResourceGroupId") != "rg-selected" || q.Get("InstanceType") != "TEST" {
				t.Fatal("missing inventory filter")
			}
			switch q.Get("CurrentPage") {
			case "1":
				return issuerJSON(`{"TotalCount":101,"InstanceList":[{"InstanceId":"already-reserved","Status":"inactive","ResourceGroupId":"rg-selected","InstanceType":"TEST"},{"InstanceId":"foreign","Status":"inactive","ResourceGroupId":"rg-other","InstanceType":"TEST"}]}`), nil
			case "2":
				return issuerJSON(`{"TotalCount":101,"InstanceList":[{"InstanceId":"free-instance","Status":"inactive","ResourceGroupId":"rg-selected","InstanceType":"TEST"}]}`), nil
			}
		case "GetInstanceDetail":
			if q.Get("InstanceId") != "free-instance" {
				t.Fatal("unexpected instance detail")
			}
			return issuerJSON(`{"InstanceId":"free-instance","InstanceType":"TEST","ResourceGroupId":"rg-selected","Status":"inactive"}`), nil
		case "UpdateInstance":
			if q.Get("InstanceId") != "free-instance" || q.Get("Domain") != req.Domain || q.Get("ValidationMethod") != "DNS" || q.Get("ContactIdList.1") != "123" || q.Get("KeyAlgorithm") != "RSA_3072" || q.Get("AutoReissue") != "disable" {
				t.Fatal("incorrect CAS application fields")
			}
			return issuerJSON(`{"RequestId":"update-accepted"}`), nil
		case "ApplyCertificate":
			if q.Get("InstanceId") != "free-instance" {
				t.Fatal("wrong application instance")
			}
			return issuerJSON(`{"RequestId":"apply-accepted"}`), nil
		}
		t.Fatalf("unexpected CAS action %q", action)
		return nil, errors.New("unexpected request")
	})
	taken := map[string]bool{"already-reserved": true}
	id, err := p.selectInstance(ctx, req, taken)
	if err != nil || id != "free-instance" {
		t.Fatalf("reservation: %q, %v", id, err)
	}
	req.InstanceID = "already-reserved"
	if _, err := p.selectInstance(ctx, req, taken); !errors.Is(err, errConflict) {
		t.Fatalf("explicit concurrent reservation: %v", err)
	}
	if err := p.Submit(ctx, id, req); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(actions, []string{"ListInstances", "ListInstances", "GetInstanceDetail", "UpdateInstance", "ApplyCertificate"}) {
		t.Fatal(actions)
	}
}

func TestAliyunInspectAndImport(t *testing.T) {
	issuer, err := newAliyun(&domain.Access{Config: map[string]any{"accessKeyId": "synthetic-id", "accessKeySecret": "synthetic-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	p := issuer.(*aliyunIssuer)
	ctx := context.Background()
	detail := `{"InstanceId":"order","InstanceType":"TEST","Status":"inactive","Domain":"www.example.test","DomainValidationList":[{"ValidationKey":"_dcv.www","ValidationType":"TXT","ValidationValue":"proof","RootDomain":"example.test."}]}`
	certificate := `{"InstanceId":"order","Id":12,"Cert":"synthetic-chain","Key":"synthetic-key"}`
	p.client.HttpClient = issuerTransport(func(r *http.Request) (*http.Response, error) {
		switch strings.Join(r.Header["x-acs-action"], "") {
		case "GetInstanceDetail":
			return issuerJSON(detail), nil
		case "GetTaskAttribute":
			if r.URL.Query().Get("TaskId") != "order" {
				t.Fatal("incorrect asynchronous task ID")
			}
			return issuerJSON(`{"TaskStatus":"processing"}`), nil
		case "GetUserCertificateDetail":
			if r.URL.Query().Get("CertId") != "12" || r.URL.Query().Get("CertFilter") != "false" {
				t.Fatal("wrong material request")
			}
			return issuerJSON(certificate), nil
		}
		return nil, errors.New("unexpected request")
	})
	s, err := p.Inspect(ctx, "order")
	if err != nil || s.State != "pending" || !slices.Equal(s.Challenges, []Challenge{{Name: "_dcv.www.example.test", Type: "TXT", Value: "proof"}}) {
		t.Fatalf("inspect: %+v %v", s, err)
	}
	detail = `{"InstanceId":"order","InstanceType":"TEST","Status":"normal","CertificateId":12}`
	material, err := p.Download(ctx, "order")
	if err != nil || material.Certificate != "synthetic-chain" || material.PrivateKey != "synthetic-key" {
		t.Fatalf("material retrieval failed: %v", err)
	}
	certificate = `{"InstanceId":"other","Id":12,"Cert":"wrong","Key":"wrong"}`
	if _, err := p.Download(ctx, "order"); !errors.Is(err, errProvider) {
		t.Fatal("accepted unrelated certificate")
	}
}

func tencentOrderArchive(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for name, contents := range map[string]string{
		"www.example.test_nginx/www.example.test_bundle.crt": "synthetic-chain",
		"www.example.test_nginx/www.example.test_bundle.pem": "duplicate-chain",
		"www.example.test_nginx/www.example.test.key":        "synthetic-key",
		"Apache/www.example.test.key":                        "wrong-format-key",
	} {
		f, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(f, contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestTencentFreeOrderLifecycle(t *testing.T) {
	issuer, err := newTencent(&domain.Access{Config: map[string]any{"secretId": "synthetic-id", "secretKey": "synthetic-secret", "projectId": float64(7)}})
	if err != nil {
		t.Fatal(err)
	}
	p := issuer.(*tencentIssuer)
	ctx := context.Background()
	status := 0
	project, plan := "7", "83"
	var actions []string
	p.client.WithHttpTransport(issuerTransport(func(r *http.Request) (*http.Response, error) {
		action := r.Header.Get("X-TC-Action")
		actions = append(actions, action)
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if action != "ApplyCertificate" && body["CertificateId"] != "order" {
			t.Fatal("wrong certificate ID")
		}
		switch action {
		case "ApplyCertificate":
			if body["PackageType"] != "83" || body["ProjectId"] != float64(7) || body["DvAuthMethod"] != "DNS" || body["CsrKeyParameter"] != "prime256v1" || body["DomainName"] != "www.example.test" {
				t.Fatal("incorrect Tencent application fields")
			}
			return issuerJSON(`{"Response":{"CertificateId":"order"}}`), nil
		case "DescribeCertificate":
			return issuerJSON(fmt.Sprintf(`{"Response":{"CertificateId":"order","ProjectId":%q,"PackageType":%q,"Domain":"www.example.test","Status":%d,"DvAuthDetail":{"DvAuthKey":"_dv","DvAuthDomain":"www.example.test","DvAuthValue":"record.example.test."}}}`, project, plan, status)), nil
		case "CompleteCertificate":
			return issuerJSON(`{"Response":{"CertificateId":"order"}}`), nil
		case "DownloadCertificate":
			return issuerJSON(fmt.Sprintf(`{"Response":{"ContentType":"application/zip","Content":%q}}`, tencentOrderArchive(t))), nil
		case "RevokeCertificate":
			return issuerJSON(`{"Response":{"RequestId":"revoke","RevokeDomainValidateAuths":[{"DomainValidateAuthKey":"_revoke","DomainValidateAuthDomain":"www.example.test","DomainValidateAuthValue":"proof"}]}}`), nil
		case "CancelAuditCertificate":
			return issuerJSON(`{"Response":{"Result":true}}`), nil
		}
		t.Fatalf("unexpected Tencent action %q", action)
		return nil, errors.New("unexpected request")
	}))
	req := OrderRequest{Domain: "www.example.test", Algorithm: "EC256", Email: "host@example.test"}
	id, err := p.Create(ctx, req)
	if err != nil || id != "order" {
		t.Fatalf("apply: %q, %v", id, err)
	}
	s, err := p.Inspect(ctx, id)
	if err != nil || s.State != "pending" || !slices.Equal(s.Challenges, []Challenge{{Name: "_dv.www.example.test", Type: "CNAME", Value: "record.example.test."}}) {
		t.Fatalf("DCV: %+v, %v", s, err)
	}
	if err := p.Verify(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := p.Cancel(ctx, id); err != nil {
		t.Fatal(err)
	}
	status = 1
	pair, err := p.Download(ctx, id)
	if err != nil || pair.PrivateKey != "synthetic-key" || pair.Certificate != "synthetic-chain" {
		t.Fatalf("download: %v", err)
	}
	proofs, err := p.Revoke(ctx, id)
	if err != nil || !slices.Equal(proofs, []Challenge{{Name: "_revoke.www.example.test", Type: "TXT", Value: "proof"}}) {
		t.Fatalf("revocation: %+v, %v", proofs, err)
	}
	for _, foreign := range [][2]string{{"9", "83"}, {"7", "3"}} {
		project, plan = foreign[0], foreign[1]
		n := len(actions)
		if _, err := p.Revoke(ctx, id); !errors.Is(err, errProvider) || !slices.Equal(actions[n:], []string{"DescribeCertificate"}) {
			t.Fatal("out-of-scope order accepted")
		}
	}
}

func TestVolcenginePinnedFreePlan(t *testing.T) {
	issuer, err := newVolcengine(&domain.Access{Config: map[string]any{"accessKeyId": "synthetic-id", "secretAccessKey": "synthetic-secret", "projectName": "selected"}})
	if err != nil {
		t.Fatal(err)
	}
	p := issuer.(*volcIssuer)
	status, kind := 200, 1
	project := "selected"
	p.client.Transport = issuerTransport(func(r *http.Request) (*http.Response, error) {
		q := r.URL.Query()
		if q.Get("Version") != "2021-06-01" || r.URL.Host != "open.volcengineapi.com" || r.Header.Get("Authorization") == "" {
			t.Fatal("wrong protocol or unsigned request")
		}
		result := ""
		switch q.Get("Action") {
		case "QuickApplyCertificate":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if r.Method != "POST" || body["plan"] != "digicert_free_standard_dv" || body["key_alg"] != "rsa" || body["organization_id"] != "org" || body["project"] != "selected" || body["common_name"] != "www.example.test" {
				t.Fatal("wrong plan, project or template")
			}
			result = `"order"`
		case "CertificateGetInstance":
			if q.Get("project_name") != "selected" || q.Get("instance_id") != "order" {
				t.Fatal("missing instance filter")
			}
			result = fmt.Sprintf(`{"content":[{"id":"order","instance_type":%d,"common_name":"www.example.test","order_status":%d,"project_name":%q,"certificate_exist":1,"ssl":{"certificate":{"chain":["synthetic-leaf","synthetic-ca"],"private_key":"synthetic-key"}}}]}`, kind, status, project)
		case "CertificateGetDcvParam":
			result = `{"validation_type":"dns_txt","domains_to_be_validated":[{"validation_domain":"_proof.www.example.test","value":"token"}]}`
		default:
			t.Fatal("unexpected order call")
		}
		return issuerJSON(`{"ResponseMetadata":{"RequestId":"r"},"Result":` + result + `}`), nil
	})
	ctx := context.Background()
	id, err := p.Create(ctx, OrderRequest{Domain: "www.example.test", Algorithm: "RSA2048", ContactID: "org"})
	if err != nil || id != "order" {
		t.Fatalf("create: %q, %v", id, err)
	}
	s, err := p.Inspect(ctx, id)
	if err != nil || s.State != "pending" || !slices.Equal(s.Challenges, []Challenge{{Name: "_proof.www.example.test", Type: "TXT", Value: "token"}}) {
		t.Fatalf("dcv: %+v %v", s, err)
	}
	status = 201
	s, err = p.Inspect(ctx, id)
	if err != nil || s.State != "cancelling" {
		t.Fatalf("cancelling: %+v %v", s, err)
	}
	status = 300
	m, err := p.Download(ctx, id)
	if err != nil || m.Certificate != "synthetic-leaf\nsynthetic-ca" || m.PrivateKey != "synthetic-key" {
		t.Fatalf("material: %v", err)
	}
	project = "unrelated"
	if _, err := p.Download(ctx, id); !errors.Is(err, errProvider) {
		t.Fatal("confirmed order from unrelated project")
	}
	project, kind = "selected", 4
	if _, err := p.Download(ctx, id); !errors.Is(err, errProvider) {
		t.Fatal("confirmed paid order")
	}
}
