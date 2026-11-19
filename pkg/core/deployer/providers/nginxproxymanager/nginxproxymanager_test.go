package nginxproxymanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func testPEM(t *testing.T) (string, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"site.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	crt, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}))
}

func testDeployer(t *testing.T, config DeployerConfig, handler http.HandlerFunc) (*Deployer, *bytes.Buffer) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	config.ServerUrl = server.URL
	config.AuthMethod = AUTH_METHOD_TOKEN
	config.ApiToken = "synthetic-api-token"
	config.AllowInsecureConnections = true
	d, err := NewDeployer(&config)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	d.SetLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return d, &buf
}

func TestTargetResolutionBeforeWrites(t *testing.T) {
	cert, key := testPEM(t)
	for _, tc := range []struct {
		caption, hostType, pattern, list string
		hostID                           int64
		reads                            int
	}{
		{"unknown host type", "unknown", "", "[]", 1, 0},
		{"invalid specified id", HOST_TYPE_PROXY, "", "[]", -1, 0},
		{"invalid selector", HOST_TYPE_PROXY, "unknown", "[]", 1, 0},
		{"unknown specified host", HOST_TYPE_STREAM, HOST_MATCH_PATTERN_SPECIFIED, `[{"id":2}]`, 1, 1},
		{"all SANs must match", HOST_TYPE_PROXY, HOST_MATCH_PATTERN_CERTSAN, `[{"id":1,"domain_names":["site.test","different.test"]}]`, 0, 1},
		{"invalid response", HOST_TYPE_DEAD, HOST_MATCH_PATTERN_CERTSAN, `[null]`, 0, 1},
		{"duplicate host IDs", HOST_TYPE_REDIRECTION, HOST_MATCH_PATTERN_SPECIFIED, `[{"id":1},{"id":1}]`, 1, 1},
	} {
		t.Run(tc.caption, func(t *testing.T) {
			n := 0
			d, _ := testDeployer(t, DeployerConfig{DeployTarget: DEPLOY_TARGET_HOST, HostType: tc.hostType, HostMatchPattern: tc.pattern, HostId: tc.hostID}, func(w http.ResponseWriter, r *http.Request) {
				n++
				if r.Method != "GET" || strings.Contains(r.URL.Path, "certificates") {
					t.Error("contacted certificate store before validating targets")
				}
				io.WriteString(w, tc.list)
			})
			if _, err := d.Deploy(context.Background(), cert, key); err == nil || n != tc.reads {
				t.Fatal("invalid target was not rejected during preflight")
			}
		})
	}
}

func TestDeploymentDoesNotLogCredentials(t *testing.T) {
	cert, key := testPEM(t)
	var calls []string
	d, logs := testDeployer(t, DeployerConfig{DeployTarget: DEPLOY_TARGET_HOST, HostType: HOST_TYPE_PROXY, HostMatchPattern: HOST_MATCH_PATTERN_CERTSAN}, func(w http.ResponseWriter, r *http.Request) {
		call := r.Method + " " + r.URL.Path
		calls = append(calls, call)
		if r.Header.Get("Authorization") != "Bearer synthetic-api-token" {
			t.Error("missing API token")
		}
		switch call {
		case "GET /api/nginx/proxy-hosts":
			io.WriteString(w, `[{"id":3,"domain_names":["site.test"],"meta":{"nginx_err":"synthetic-host-secret"}},{"id":7,"domain_names":["other.test"]}]`)
		case "GET /api/nginx/certificates":
			io.WriteString(w, `[{"id":1,"meta":{"certificate_key":"synthetic-existing-private-key"}}]`)
		case "POST /api/nginx/certificates":
			io.WriteString(w, `{"id":11,"nice_name":"synthetic-private-displayname"}`)
		case "POST /api/nginx/certificates/11/upload":
			file, _, err := r.FormFile("certificate_key")
			if err != nil {
				t.Error("missing uploaded key")
				break
			}
			defer file.Close()
			b, err := io.ReadAll(file)
			if err != nil || string(b) != key {
				t.Error("wrong uploaded key")
			}
			json.NewEncoder(w).Encode(map[string]string{"certificate_key": key, "certificate": cert})
		case "PUT /api/nginx/proxy-hosts/3":
			var v struct {
				Cert int `json:"certificate_id"`
			}
			if json.NewDecoder(r.Body).Decode(&v) != nil || v.Cert != 11 {
				t.Error("wrong host binding")
			}
			io.WriteString(w, `{"id":3,"meta":{"nginx_err":"synthetic-host-secret"}}`)
		default:
			t.Error("unexpected request")
		}
	})
	if _, err := d.Deploy(context.Background(), cert, key); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(calls, []string{"GET /api/nginx/proxy-hosts", "GET /api/nginx/certificates", "POST /api/nginx/certificates", "POST /api/nginx/certificates/11/upload", "PUT /api/nginx/proxy-hosts/3"}) {
		t.Fatal("wrong operation order")
	}
	for _, secret := range []string{"synthetic-", "PRIVATE KEY", "BEGIN CERTIFICATE", strings.Split(key, "\n")[1]} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("workflow log contains provider response, credential or key material")
		}
	}
}

func TestSDKAndReplacementDoNotEchoProviderErrors(t *testing.T) {
	cert, key := testPEM(t)
	for _, tc := range []struct {
		label  string
		status int
		body   string
	}{
		{"HTTP error", 400, `{"error":"synthetic-remote-secret"}`},
		{"API error", 200, `{"error":{"code":100,"message":"synthetic-remote-secret"}}`},
		{"malformed response", 200, `{synthetic-remote-secret`},
		{"null response", 200, `null`},
	} {
		t.Run(tc.label, func(t *testing.T) {
			d, logs := testDeployer(t, DeployerConfig{DeployTarget: DEPLOY_TARGET_CERTIFICATE, CertificateId: 1}, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/nginx/certificates/1/upload" {
					t.Error("continued after failed replacement")
				}
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			})
			_, err := d.Deploy(context.Background(), cert, key)
			if err == nil {
				t.Fatal("accepted invalid response")
			}
			result := logs.String() + err.Error()
			for _, s := range []string{"synthetic-", "PRIVATE KEY", "BEGIN CERTIFICATE", strings.Split(key, "\n")[1]} {
				if strings.Contains(result, s) {
					t.Fatal("workflow error or log contains provider data")
				}
			}
		})
	}
}

func TestExistingBindingDoesNotWrite(t *testing.T) {
	cert, key := testPEM(t)
	calls := 0
	d, _ := testDeployer(t, DeployerConfig{DeployTarget: DEPLOY_TARGET_HOST, HostType: HOST_TYPE_STREAM, HostId: 8}, func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.Method + " " + r.URL.Path {
		case "GET /api/nginx/streams":
			io.WriteString(w, `[{"id":8,"certificate_id":4}]`)
		case "GET /api/nginx/certificates":
			json.NewEncoder(w).Encode([]map[string]any{{"id": 4, "meta": map[string]string{"certificate": cert, "certificate_key": key}}})
		default:
			t.Error("issued write for existing binding")
		}
	})
	if _, err := d.Deploy(context.Background(), cert, key); err != nil || calls != 2 {
		t.Fatal("existing binding was not reused")
	}
}

func TestCertificateReplaceAndReload(t *testing.T) {
	cert, key := testPEM(t)
	var calls []string
	d, _ := testDeployer(t, DeployerConfig{DeployTarget: DEPLOY_TARGET_CERTIFICATE, CertificateId: 42}, func(w http.ResponseWriter, r *http.Request) {
		call := r.Method + " " + r.URL.Path
		calls = append(calls, call)
		switch call {
		case "POST /api/nginx/certificates/42/upload":
			io.WriteString(w, "{}")
		case "GET /api/settings/default-site":
			io.WriteString(w, `{"value":"404"}`)
		case "PUT /api/settings/default-site":
			var v struct {
				Value string `json:"value"`
			}
			if json.NewDecoder(r.Body).Decode(&v) != nil || v.Value != "404" {
				t.Error("changed default site while reloading certificate")
			}
			io.WriteString(w, "{}")
		default:
			t.Error("unexpected request")
		}
	})
	if _, err := d.Deploy(context.Background(), cert, key); err != nil || len(calls) != 3 {
		t.Fatal("replacement and reload did not finish")
	}
}

func TestUploadRefusesRedirect(t *testing.T) {
	cert, key := testPEM(t)
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("redirect forwarded a certificate upload") }))
	t.Cleanup(other.Close)
	d, _ := testDeployer(t, DeployerConfig{DeployTarget: DEPLOY_TARGET_CERTIFICATE, CertificateId: 1}, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	})
	if _, err := d.Deploy(context.Background(), cert, key); err == nil {
		t.Fatal("accepted redirect")
	}
}
