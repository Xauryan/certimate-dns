package baotapanelgo

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func sampleIISCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "site.example.test"}, DNSNames: []string{"site.example.test", "www.example.test"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func TestIISDomainBindingUsesScopedTemporaryPFX(t *testing.T) {
	cert, key := sampleIISCertificate(t)
	var lastPassword string
	for _, outcome := range []string{"success", "upload-failed", "bind-failed", "remove-failed", "not-iis"} {
		t.Run(outcome, func(t *testing.T) {
			var paths []string
			var pfx []byte
			var uploaded, password string
			var bound []string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				paths = append(paths, r.URL.Path)
				response := `{"status":true}`
				switch r.URL.Path {
				case "/panel/get_config":
					response = `{"config":{"webserver":"iis"},"paths":{"soft":"C:/BtSoft"}}`
					if outcome == "not-iis" {
						response = `{"site":{"webserver":"nginx"}}`
					}
				case "/files/upload":
					f, _, err := r.FormFile("blob")
					if err != nil {
						t.Error(err)
						return
					}
					pfx, err = io.ReadAll(f)
					f.Close()
					if err != nil {
						t.Error(err)
						return
					}
					file := r.FormValue("filename")
					if r.FormValue("path") != "C:/BtSoft/temp/ssl/certimate" || len(file) != 68 || !strings.HasSuffix(file, ".pfx") || r.FormValue("size") != strconv.Itoa(len(pfx)) {
						t.Error("invalid temporary file")
					}
					uploaded = r.FormValue("path") + "/" + file
					if outcome == "upload-failed" {
						response = `{"status":false}`
					}
				case "/site/set_site_domain_ssl":
					if uploaded == "" || r.FormValue("path") != uploaded {
						t.Error("incorrect PFX path")
					}
					bound = append(bound, r.FormValue("domain"))
					password = r.FormValue("password")
					_, leaf, err := pkcs12.Decode(pfx, password)
					if err != nil || leaf.Subject.CommonName != "site.example.test" {
						t.Error("PFX did not recover the requested certificate")
					}
					if outcome == "bind-failed" {
						response = `{"status":false,"msg":"` + password + `"}`
					}
				case "/files/remove_file":
					if uploaded == "" || r.FormValue("filename") != uploaded {
						t.Error("cleanup must target exactly the uploaded file")
					}
					if outcome == "remove-failed" {
						response = `{}`
					}
				default:
					t.Errorf("unexpected request to %s", r.URL.Path)
				}
				if r.FormValue("request_token") == "" {
					t.Error("unsigned request")
				}
				_, _ = w.Write([]byte(response))
			}))
			defer srv.Close()
			d, err := NewDeployer(&DeployerConfig{ServerUrl: srv.URL, ApiKey: "fixture-key", AllowInsecureConnections: true, SiteType: "iis-domain", SiteNames: []string{"site.example.test", "www.example.test"}})
			if err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			d.SetLogger(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
			_, err = d.Deploy(context.Background(), cert, key)
			if (err == nil) != (outcome == "success") {
				t.Fatalf("unexpected outcome %s: %v", outcome, err)
			}
			if outcome == "not-iis" {
				if !slices.Equal(paths, []string{"/panel/get_config"}) {
					t.Errorf("unexpected side effects %v", paths)
				}
				return
			}
			if n := len(paths); n < 3 || paths[n-1] != "/files/remove_file" || paths[1] != "/files/upload" {
				t.Errorf("unexpected operations %v", paths)
			}
			if outcome == "upload-failed" {
				if len(bound) != 0 {
					t.Error("bound unconfirmed upload")
				}
				return
			}
			if len(password) < 20 || password == lastPassword {
				t.Error("PFX password must be fresh per upload")
			}
			lastPassword = password
			if strings.Contains(logs.String(), password) || strings.Contains(logs.String(), "PRIVATE KEY") || err != nil && strings.Contains(err.Error(), password) {
				t.Error("sensitive material in diagnostics")
			}
			if outcome == "bind-failed" {
				if !slices.Equal(bound, []string{"site.example.test"}) {
					t.Error("unexpected retry after failed bind")
				}
			} else if !slices.Equal(bound, d.config.SiteNames) {
				t.Errorf("unexpected domain bindings %v", bound)
			}
		})
	}
}
