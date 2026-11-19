package dnsmgrhosts

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testKeyPair(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"example.test"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: enc}))
}

func newTestPanel(t *testing.T, provider, target string, handler http.HandlerFunc) *mwPanel {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	p, err := New(provider, map[string]any{"serverUrl": srv.URL + "/panel", "appId": "sample-id", "appSecret": "sample-secret"}, map[string]any{"target": target})
	if err != nil {
		t.Fatal(err)
	}
	deployer := p.(*mwPanel)
	deployer.client.Transport = srv.Client().Transport
	return deployer
}

func TestMWPanelDeployTargets(t *testing.T) {
	cert, key := testKeyPair(t)
	for _, provider := range []string{"mwpanel", "mwpanel-console"} {
		t.Run(provider, func(t *testing.T) {
			var count atomic.Int32
			p := newTestPanel(t, provider, "example.test\n example.test \n", func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				if r.Method != "POST" || r.Header.Get("App-Id") != "sample-id" || r.Header.Get("App-Secret") != "sample-secret" || r.URL.RawQuery != "" {
					t.Error("invalid request method, authentication or query")
				}
				if err := r.ParseForm(); err != nil {
					t.Error("invalid form")
					return
				}
				if provider == "mwpanel" {
					if r.URL.Path != "/panel/site/set_ssl" || r.PostForm.Get("type") != "1" || r.PostForm.Get("siteName") != "example.test" || r.PostForm.Get("key") != key || r.PostForm.Get("csr") != cert {
						t.Error("invalid site certificate request")
					}
				} else if r.URL.Path != "/panel/setting/save_panel_ssl" || r.PostForm.Get("choose") != "local" || r.PostForm.Get("privateKey") != key || r.PostForm.Get("certPem") != cert {
					t.Error("invalid console certificate request")
				}
				io.WriteString(w, `{"status":true}`)
			})
			if _, err := p.Deploy(context.Background(), cert, key); err != nil {
				t.Fatal(err)
			}
			if count.Load() != 1 {
				t.Fatal("unexpected number of upload requests")
			}
		})
	}
}

func TestMWPanelPartialFailureAndRedirect(t *testing.T) {
	cert, key := testKeyPair(t)
	var count atomic.Int32
	p := newTestPanel(t, "mwpanel", "one.test\ntwo.test\nthree.test", func(w http.ResponseWriter, r *http.Request) {
		n := count.Add(1)
		if n == 1 {
			io.WriteString(w, `{"status":true}`)
			return
		}
		io.WriteString(w, `{"status":false,"msg":"sample-secret"}`)
	})
	_, err := p.Deploy(context.Background(), cert, key)
	if err == nil || !strings.Contains(err.Error(), "1 of 3") || strings.Contains(err.Error(), "sample-secret") || count.Load() != 2 {
		t.Fatal("incorrect partial-failure handling")
	}
	q := newTestPanel(t, "mwpanel-console", "", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/unexpected" {
			t.Error("forwarded a certificate or credential on redirect")
		}
		http.Redirect(w, r, "/unexpected", http.StatusTemporaryRedirect)
	})
	if _, err := q.Deploy(context.Background(), cert, key); err == nil {
		t.Fatal("accepted redirect")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := q.Deploy(ctx, cert, key); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored cancellation")
	}
}

func TestMWPanelInvalidConfigurationAndKey(t *testing.T) {
	good := map[string]any{"serverUrl": "https://panel.example.test", "appId": "sample-id", "appSecret": "sample-secret"}
	for _, site := range []string{"", "../another", "invalid/path", "site?name", "punctuated;name"} {
		if _, err := New("mwpanel", good, map[string]any{"target": site}); err == nil {
			t.Fatal("accepted invalid site name")
		}
	}
	for _, address := range []string{"http://panel.example.test", "https://user@panel.example.test", "https://panel.example.test?secret", "/relative"} {
		if _, err := New("mwpanel-console", map[string]any{"serverUrl": address, "appId": "sample-id", "appSecret": "sample-secret"}, nil); err == nil {
			t.Fatal("accepted invalid HTTPS endpoint")
		}
	}
	p := newTestPanel(t, "mwpanel-console", "", func(http.ResponseWriter, *http.Request) { t.Error("sent invalid key pair") })
	cert, _ := testKeyPair(t)
	_, otherKey := testKeyPair(t)
	if _, err := p.Deploy(context.Background(), cert, otherKey); err == nil {
		t.Fatal("accepted mismatched key pair")
	}
}
