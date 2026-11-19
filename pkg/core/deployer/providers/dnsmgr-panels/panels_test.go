package dnsmgrpanels

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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

func syntheticPair(t *testing.T) (string, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(10), DNSNames: []string{"site.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	crt, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
}

func testPanel(t *testing.T, provider string, access, config map[string]any, serve http.HandlerFunc) *panel {
	t.Helper()
	s := httptest.NewTLSServer(serve)
	t.Cleanup(s.Close)
	access["serverUrl"] = s.URL
	p, err := New(provider, access, config)
	if err != nil {
		t.Fatal(err)
	}
	result := p.(*panel)
	result.client.Transport = s.Client().Transport
	return result
}

func TestKangle(t *testing.T) {
	cert, key := syntheticPair(t)
	for _, tc := range []struct {
		provider        string
		sso             bool
		target, domains string
	}{
		{"kangle", false, "", ""},
		{"kangle", true, "site.test", ""},
		{"kangleadmin", true, "vhost", "site.test"},
		{"kangleadmin", true, "vhost", ""},
		{"kangleadmin-console", true, "", ""},
	} {
		t.Run(tc.provider+"/"+tc.domains+"/"+tc.target, func(t *testing.T) {
			access := map[string]any{"username": "test-user", "adminPath": "/test-admin"}
			if tc.sso {
				access["securityKey"] = "test-secret"
			} else {
				access["password"] = "test-secret"
			}
			loginRoot := "/vhost"
			if tc.provider != "kangle" {
				loginRoot = "/test-admin"
			}
			var logins, updates atomic.Int32
			instance := testPanel(t, tc.provider, access, map[string]any{"target": tc.target, "domains": tc.domains}, func(w http.ResponseWriter, r *http.Request) {
				action := r.URL.Query().Get("a")
				cookie, err := r.Cookie("session")
				hasCookie := err == nil && cookie.Value == "test-value"
				switch {
				case action == "hello":
					if !tc.sso || r.URL.Path != loginRoot+"/index.php" {
						t.Error("unexpected SSO endpoint")
					}
					http.SetCookie(w, &http.Cookie{Name: "session", Value: "test-value", Path: "/", Secure: true})
					http.Redirect(w, r, "/callback?r=challenge", http.StatusFound)
				case action == "login":
					logins.Add(1)
					if tc.sso {
						signature := md5.Sum([]byte("challengetest-userchallengetest-secret"))
						if r.Method != "GET" || !hasCookie || r.URL.Query().Get("s") != hex.EncodeToString(signature[:]) {
							t.Error("invalid SSO request")
						}
					} else {
						if r.Method != "POST" || r.PostFormValue("username") != "test-user" || r.PostFormValue("passwd") != "test-secret" || r.Referer() == "" {
							t.Error("invalid password login request")
						}
						http.SetCookie(w, &http.Cookie{Name: "session", Value: "test-value", Path: "/", Secure: true})
					}
					http.Redirect(w, r, "/", http.StatusFound)
				case action == "impLogin":
					if r.URL.Path != loginRoot+"/index.php" || r.URL.Query().Get("name") != "vhost" || !hasCookie {
						t.Error("invalid virtual host selection")
					}
					http.Redirect(w, r, "/vhost/", http.StatusFound)
				case r.Method == "GET" && r.URL.Path == "/vhost/":
					if !hasCookie {
						t.Error("missing vhost session")
					}
				case r.Method == "POST":
					updates.Add(1)
					if !hasCookie {
						t.Error("missing upload session")
					}
					if tc.provider == "kangleadmin-console" {
						if r.URL.Path != loginRoot+"/index.php" || r.URL.Query().Get("c") != "security" || r.PostFormValue("crt") != cert || r.PostFormValue("key") != key {
							t.Error("invalid console upload")
						}
					} else {
						perDomain := tc.domains != "" || (tc.provider == "kangle" && tc.target != "")
						if (action == "domainSsl") != perDomain || (perDomain && r.PostFormValue("domain") != "site.test") || r.PostFormValue("certificate") != cert || r.PostFormValue("certificate_key") != key {
							t.Error("invalid site upload")
						}
					}
					io.WriteString(w, "<script>alert('操作成功')</script>")
				default:
					t.Error("unexpected request")
				}
			})
			if _, err := instance.Deploy(context.Background(), cert, key); err != nil {
				t.Fatal(err)
			}
			if logins.Load() != 1 || updates.Load() != 1 {
				t.Fatal("missing login or update")
			}
		})
	}
}

func TestCloudPanel(t *testing.T) {
	cert, key := syntheticPair(t)
	var count atomic.Int32
	p := testPanel(t, "cloudpanel", map[string]any{"username": "test-user", "password": "test-secret"}, map[string]any{"target": "site.test"}, func(w http.ResponseWriter, r *http.Request) {
		switch count.Add(1) {
		case 1:
			if r.Method != "GET" || r.URL.Path != "/login" {
				t.Error("invalid login path")
			}
			http.SetCookie(w, &http.Cookie{Name: "test-session", Value: "test-value", Path: "/", Secure: true})
			io.WriteString(w, `<input value="csrf&amp;1" name="_csrf_token">`)
		case 2:
			if _, err := r.Cookie("test-session"); err != nil || r.PostFormValue("_csrf_token") != "csrf&1" || r.PostFormValue("password") != "test-secret" {
				t.Error("invalid login fields or session")
			}
			http.Redirect(w, r, "/", http.StatusFound)
		case 3:
			if r.Method != "GET" || r.URL.Path != "/site/site.test/certificate/import" {
				t.Error("invalid import path")
			}
			io.WriteString(w, `<input id='site_import_certificate__token' value='csrf2'>`)
		case 4:
			if r.PostFormValue("site_import_certificate[certificate]") != cert || r.PostFormValue("site_import_certificate[privateKey]") != key || r.PostFormValue("site_import_certificate[_token]") != "csrf2" {
				t.Error("invalid import fields")
			}
			http.Redirect(w, r, "/site/site.test/certificates", http.StatusSeeOther)
		default:
			t.Error("unexpected request")
		}
	})
	if _, err := p.Deploy(context.Background(), cert, key); err != nil {
		t.Fatal(err)
	}
	if count.Load() != 4 {
		t.Fatal("missing upload")
	}
}

func TestDirectAdminPartialFailure(t *testing.T) {
	cert, key := syntheticPair(t)
	var count atomic.Int32
	p := testPanel(t, "directadmin", map[string]any{"username": "test-user", "password": "test-secret"}, map[string]any{"target": "site.test,SITE.TEST\nother.test\nnext.test"}, func(w http.ResponseWriter, r *http.Request) {
		n := count.Add(1)
		user, password, ok := r.BasicAuth()
		if !ok || user != "test-user" || password != "test-secret" || r.URL.Path != "/CMD_API_SSL" || r.PostFormValue("action") != "save" {
			t.Error("invalid API request")
		}
		bundle := r.PostFormValue("certificate")
		block, rest := pem.Decode([]byte(bundle))
		if block == nil || block.Type != "EC PRIVATE KEY" || string(rest) != cert {
			t.Error("invalid certificate bundle")
		}
		if _, err := tls.X509KeyPair(rest, []byte(bundle)); err != nil {
			t.Error("key conversion failed")
		}
		switch n {
		case 1:
			io.WriteString(w, "error=0")
		case 2:
			io.WriteString(w, `{"error":"1","details":"test-secret"}`)
		default:
			t.Error("continued after failure")
		}
	})
	_, err := p.Deploy(context.Background(), cert, key)
	if err == nil || !strings.Contains(err.Error(), "1 of 3") || strings.Contains(err.Error(), "test-secret") || count.Load() != 2 {
		t.Fatal("partial failure incorrectly reported")
	}
}

func TestPanelFailures(t *testing.T) {
	cert, key := syntheticPair(t)
	_, otherKey := syntheticPair(t)
	var requests atomic.Int32
	p := testPanel(t, "cloudpanel", map[string]any{"username": "test-user", "password": "test-secret"}, map[string]any{"target": "site.test"}, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Redirect(w, r, "https://other.invalid/login", http.StatusFound)
	})
	if _, err := p.Deploy(context.Background(), cert, otherKey); err == nil || requests.Load() != 0 {
		t.Fatal("sent a mismatched key")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Deploy(ctx, cert, key); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored cancellation")
	}
	if _, err := p.Deploy(context.Background(), cert, key); err == nil || requests.Load() != 1 {
		t.Fatal("external redirect accepted")
	}
	if _, err := New("directadmin", map[string]any{"serverUrl": "http://panel.test", "username": "test-user", "password": "test-secret"}, map[string]any{"target": "site.test"}); err == nil {
		t.Fatal("accepted insecure transport")
	}
	if _, err := New("kangle", map[string]any{"serverUrl": "https://panel.test", "username": "test-user", "password": "test-secret"}, map[string]any{"target": []string{"site.test"}}); err == nil {
		t.Fatal("invalid domain list selected account-level deploy")
	}
}

func TestKangleAdminRejectedSwitchDoesNotUpdatePreviousSite(t *testing.T) {
	cert, key := syntheticPair(t)
	var uploads atomic.Int32
	p := testPanel(t, "kangleadmin", map[string]any{"username": "test-user", "securityKey": "test-secret"}, map[string]any{"target": "site1\nsite2"}, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch q.Get("a") {
		case "hello":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "test-sso", Path: "/", Secure: true})
			http.Redirect(w, r, "/?r=test", http.StatusFound)
		case "login":
			http.Redirect(w, r, "/admin/", http.StatusFound)
		case "impLogin":
			if q.Get("name") == "site1" {
				http.Redirect(w, r, "/vhost/", http.StatusFound)
			} else {
				http.Redirect(w, r, "/vhost/?c=session&a=loginForm", http.StatusFound)
			}
		case "ssl":
			uploads.Add(1)
			io.WriteString(w, "成功")
		default:
			if r.Method != "GET" || r.URL.Path != "/vhost/" {
				t.Error("unexpected request")
			}
		}
	})
	_, err := p.Deploy(context.Background(), cert, key)
	if err == nil || !strings.Contains(err.Error(), "1 of 2") || uploads.Load() != 1 {
		t.Fatal("failed site switch could update the previous host")
	}
}
