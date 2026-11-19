package dnscert

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
)

type ucloudTransport func(*http.Request) (*http.Response, error)

func (f ucloudTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func ucloudZIP(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var storage bytes.Buffer
	w := zip.NewWriter(&storage)
	for name, text := range entries {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(f, text); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return storage.Bytes()
}

func TestUCloudOrderWireContract(t *testing.T) {
	ca, err := newUCloud(&domain.Access{Config: map[string]any{"publicKey": "synthetic-public", "privateKey": "synthetic-private", "projectId": "synthetic-project"}})
	if err != nil {
		t.Fatal(err)
	}
	u := ca.(*ucloudIssuer)
	archive := ucloudZIP(t, map[string]string{"Nginx/public.pem": "synthetic-chain", "Nginx/private.key": "synthetic-key", "Apache/private.key": "different-format"})
	var actions []string
	status := "PENDING"
	name := ""
	storageCalls := 0
	u.client.Transport = ucloudTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "synthetic.cn-bj.ufileos.com" {
			storageCalls++
			if req.Method != "GET" || req.Body != nil || req.Header.Get("Authorization") != "" {
				t.Fatal("unexpected storage credential or method")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(archive))}, nil
		}
		if req.Method != "POST" || req.URL.String() != "https://api.ucloud.cn/" || req.Header.Get("Content-Type") != "application/json" {
			t.Fatal("incorrect API request")
		}
		var params map[string]any
		if err := json.NewDecoder(req.Body).Decode(&params); err != nil {
			t.Fatal(err)
		}
		signature := params["Signature"]
		delete(params, "Signature")
		if params["PublicKey"] != "synthetic-public" || params["ProjectId"] != "synthetic-project" || signature != u.credentials.VerifyAc(params) {
			t.Fatal("invalid project or signature")
		}
		action := params["Action"].(string)
		actions = append(actions, action)
		out := map[string]any{"Action": action + "Response", "RetCode": 0}
		switch action {
		case "GetCertificateList":
			if params["Mode"] != "free" {
				t.Fatal("incorrect plan list")
			}
			out["TotalCount"] = 0
		case "PurchaseCertificate":
			if params["CertificateBrand"] != "TrustAsia" || params["CertificateName"] != ucloudPlan || params["DomainsCount"] != float64(1) || params["ValidYear"] != "1" {
				t.Fatal("incorrect plan")
			}
			out["CertificateID"] = 177
		case "GetCertificateDetailInfo":
			out["CertificateInfo"] = map[string]any{"CertificateID": 177, "Mode": "purchase", "Brand": "TrustAsia", "Name": ucloudPlan, "Domains": name, "StateCode": status}
		case "ComplementCSRInfo":
			if params["CSRKeyParameter"] != "prime256v1" || params["CSREncryptAlgo"] != "ECDSA" || params["DVAuthMethod"] != "DNS" || params["AdminName"] != "test" || params["CompanyName"] != "synthetic org" {
				t.Fatal("incorrect CSR or contact")
			}
			name = params["Domains"].(string)
		case "GetDVAuthInfo":
			out["AuthMethod"] = "DNS"
			out["Auths"] = []any{map[string]string{"Domain": name, "AuthKey": "_dns." + name, "AuthValue": "synthetic-validation", "AuthType": "DNS_TXT"}}
		case "DownloadCertificate":
			out["CertificateUrl"] = "https://synthetic.cn-bj.ufileos.com/archive.zip?ticket=synthetic"
		case "RevokeCertificate":
			if params["Reason"] == "" {
				t.Fatal("missing reason")
			}
			status = "REVOKED"
		case "CancelCertificateOrder":
			status = "CANCELLED"
		default:
			t.Fatalf("unexpected action %s", action)
		}
		if action != "GetCertificateList" && action != "PurchaseCertificate" && params["CertificateID"] != float64(177) {
			t.Fatal("incorrect remote id")
		}
		data, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data))}, nil
	})
	ctx := context.Background()
	in := OrderRequest{Domain: "www.example.test", Algorithm: "EC256", ContactName: "test", Organization: "synthetic org"}
	if err := u.Check(ctx); err != nil {
		t.Fatal(err)
	}
	id, err := u.Create(ctx, in)
	if id != "177" || err != nil {
		t.Fatalf("reserve id=%q err=%v", id, err)
	}
	if state, err := u.Inspect(ctx, id); err != nil || state.State != "reserved" {
		t.Fatalf("reservation %v %v", state.State, err)
	}
	if err := u.Submit(ctx, id, in); err != nil {
		t.Fatal(err)
	}
	state, err := u.Inspect(ctx, id)
	if err != nil || state.State != "pending" || len(state.Challenges) != 1 || state.Challenges[0].Type != "TXT" {
		t.Fatalf("validation %v %v", state.State, err)
	}
	count := len(actions)
	if err := u.Verify(ctx, id); err != nil || len(actions) != count {
		t.Fatal("DNS validation should progress asynchronously")
	}
	status = "COMPLETED"
	if state, err = u.Inspect(ctx, id); err != nil || state.State != "issued" {
		t.Fatalf("issuance %v %v", state.State, err)
	}
	m, err := u.Download(ctx, id)
	if err != nil || m.PrivateKey != "synthetic-key" || m.Certificate != "synthetic-chain" || storageCalls != 1 {
		t.Fatal("failed to read unique Nginx key and chain")
	}
	if _, err = u.Revoke(ctx, id); err != nil {
		t.Fatal(err)
	}
	if state, err = u.Inspect(ctx, id); err != nil || state.State != "revoked" {
		t.Fatalf("revocation %v %v", state.State, err)
	}
	status = "PENDING"
	if err = u.Cancel(ctx, id); err != nil {
		t.Fatal(err)
	}
	if state, err = u.Inspect(ctx, id); err != nil || state.State != "cancelled" {
		t.Fatalf("cancellation %v %v", state.State, err)
	}
}

func TestUCloudDownloadRejectsUnsafeArtifacts(t *testing.T) {
	for _, link := range []string{"https://example.test/archive", "http://test.ufileos.com/archive", "https://test.ufileos.com:1234/archive", "https://test.ufileos.com.example.test/archive", "https://test@test.ufileos.com/archive", "https://127.0.0.1/archive"} {
		tc, err := newUCloud(&domain.Access{Config: map[string]any{"publicKey": "synthetic-public", "privateKey": "synthetic-private"}})
		if err != nil {
			t.Fatal(err)
		}
		u := tc.(*ucloudIssuer)
		u.client.Transport = ucloudTransport(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host != "api.ucloud.cn" {
				t.Fatal("unexpected storage request")
			}
			b, _ := json.Marshal(map[string]any{"Action": "DownloadCertificateResponse", "RetCode": 0, "CertificateUrl": link})
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b))}, nil
		})
		if _, err := u.Download(context.Background(), "10"); !errors.Is(err, errProvider) {
			t.Errorf("untrusted location accepted")
		}
	}
	for _, entries := range []map[string]string{
		{"Nginx/one.pem": "synthetic", "Nginx/one.key": "synthetic", "Nginx/two.key": "synthetic"},
		{"Nginx/one.pem": "synthetic", "Nginx/../one.key": "synthetic"},
		{"Nginx/one.pem": strings.Repeat("a", 256<<10+1), "Nginx/one.key": "synthetic"},
	} {
		if _, err := ucloudNginxMaterial(ucloudZIP(t, entries)); !errors.Is(err, errProvider) {
			t.Fatal("invalid archive accepted")
		}
	}
}

func TestUCloudRejectsAmbiguousOrUnrelatedResponses(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"missing response code", `{"Action":"GetCertificateDetailInfoResponse"}`},
		{"wrong action", `{"RetCode":0,"Action":"GetCertificateListResponse"}`},
		{"provider error with sensitive detail", `{"RetCode":123,"Action":"GetCertificateDetailInfoResponse","Message":"synthetic confidential detail"}`},
		{"other instance", `{"RetCode":0,"Action":"GetCertificateDetailInfoResponse","CertificateInfo":{"CertificateID":23,"Brand":"TrustAsia","Mode":"free","StateCode":"COMPLETED","Domains":"www.example.test"}}`},
		{"other plan", `{"RetCode":0,"Action":"GetCertificateDetailInfoResponse","CertificateInfo":{"CertificateID":22,"Brand":"TrustAsia","Mode":"purchase","Name":"paidSSL","StateCode":"COMPLETED","Domains":"www.example.test"}}`},
		{"other hosting mode", `{"RetCode":0,"Action":"GetCertificateDetailInfoResponse","CertificateInfo":{"CertificateID":22,"Brand":"TrustAsia","Mode":"trust","StateCode":"COMPLETED","Domains":"www.example.test"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := newUCloud(&domain.Access{Config: map[string]any{"publicKey": "synthetic", "privateKey": "synthetic"}})
			if err != nil {
				t.Fatal(err)
			}
			u := ca.(*ucloudIssuer)
			calls := 0
			u.client.Transport = ucloudTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			if _, err := u.Inspect(context.Background(), "22"); err != errProvider || calls != 1 {
				t.Fatal("expected single failed lookup and opaque error")
			}
			if _, err := u.Inspect(context.Background(), "022"); err != errInput || calls != 1 {
				t.Fatal("invalid remote ID reached provider")
			}
		})
	}
}
