package dnsmgredge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func testPair(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	crt := x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"example.test", "*.example.test", "one.example.test"}}
	der, err := x509.CreateCertificate(rand.Reader, &crt, &crt, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: enc}))
}

func localDeployer(t *testing.T, provider string, config map[string]any, handler http.HandlerFunc) *deployer {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	access := map[string]any{"serverUrl": server.URL, "username": "模拟", "apiPassword": "demo-west", "password": "demo-panel", "apiToken": "demo-token", "apiKey": "demo-key"}
	raw, err := New(provider, access, config)
	if err != nil {
		t.Fatal(err)
	}
	d := raw.(*deployer)
	d.baseURL = server.URL
	d.client.Transport = server.Client().Transport
	return d
}

func TestLuckyPreflightAndUpload(t *testing.T) {
	cert, key := testPair(t)
	for _, tc := range []struct {
		name           string
		mapped, update bool
	}{
		{"preserve_settings", false, true}, {"filesystem_entry", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var uploads int
			d := localDeployer(t, "lucky", nil, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/ssl" || r.Header.Get("openToken") != "demo-token" {
					t.Error("incorrect endpoint or authentication")
				}
				if r.Method == http.MethodGet {
					fmt.Fprintf(w, `{"ret":0,"list":[{"Key":"x","Enable":false,"AllSyncClient":true,"Remark":"testing","CertsInfo":{"Domains":["example.test"]}},{"Key":"y","Enable":true,"MappingToPath":%t,"CertsInfo":{"Domains":["*.example.test"]}},{"Key":"other","CertsInfo":{"Domains":["other.test"]}}]}`, tc.mapped)
					return
				}
				if !tc.update || r.Method != http.MethodPut {
					t.Error("unexpected mutation")
				}
				var payload map[string]any
				if json.NewDecoder(r.Body).Decode(&payload) != nil || payload["KeyBase64"] != base64.StdEncoding.EncodeToString([]byte(key)) || payload["CertBase64"] != base64.StdEncoding.EncodeToString([]byte(cert)) {
					t.Error("invalid upload payload")
				}
				if uploads == 0 && (payload["Key"] != "x" || payload["Enable"] != false || payload["AllSyncClient"] != true || payload["Remark"] != "testing") {
					t.Error("entry settings changed")
				}
				uploads++
				io.WriteString(w, `{"ret":0}`)
			})
			_, err := d.Deploy(context.Background(), cert, key)
			if tc.update && (err != nil || uploads != 2) || !tc.update && (err == nil || uploads != 0) {
				t.Fatalf("uploads=%d, err=%v", uploads, err)
			}
		})
	}
}

func TestXPResolvesAllTargetsBeforeUpload(t *testing.T) {
	cert, key := testPair(t)
	for _, tc := range []struct {
		target    string
		wantCalls int
		wantErr   bool
	}{
		{"site-a\nsite-a", 1, false}, {"site-a\nmissing", 0, true}, {"site-a\nsite-b", 2, true},
	} {
		var calls int
		d := localDeployer(t, "xp", map[string]any{"target": tc.target}, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("XP-API-KEY") != "demo-key" {
				t.Error("missing XP authentication")
			}
			if r.Method == http.MethodGet && r.URL.Path == "/openApi/siteList" {
				io.WriteString(w, `{"code":1000,"data":[{"name":"site-a","id":"12"},{"name":"site-b","id":13}]}`)
				return
			}
			if r.Method != http.MethodPost || r.URL.Path != "/openApi/setSSL" {
				t.Error("wrong XP endpoint")
			}
			var body struct {
				ID       int
				Key, Pem string
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Key != key || body.Pem != cert || body.ID != 12+calls {
				t.Error("invalid XP upload")
			}
			calls++
			if calls > 1 {
				io.WriteString(w, `{"code":500,"message":"demo-secret"}`)
				return
			}
			io.WriteString(w, `{"code":1000}`)
		})
		_, err := d.Deploy(context.Background(), cert, key)
		if (err != nil) != tc.wantErr || calls != tc.wantCalls || err != nil && strings.Contains(err.Error(), "demo-secret") {
			t.Fatalf("XP calls=%d err=%v", calls, err)
		}
	}
}

func TestUUSECLoginAndUpload(t *testing.T) {
	cert, key := testPair(t)
	var calls int
	d := localDeployer(t, "uusec", map[string]any{"target": "42", "name": "demo"}, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			var login struct{ Usr, Pwd string }
			if r.Method != "POST" || r.URL.Path != "/api/v1/users/login" || json.NewDecoder(r.Body).Decode(&login) != nil || login.Usr != "模拟" || login.Pwd != "demo-panel" {
				t.Error("invalid UUSEC login")
			}
			io.WriteString(w, `{"token":"demo-session"}`)
			return
		}
		var data struct {
			ID, Type       int
			Name, Crt, Key string
		}
		if r.Method != "PUT" || r.URL.Path != "/api/v1/certs" || r.Header.Get("Authorization") != "Bearer demo-session" || json.NewDecoder(r.Body).Decode(&data) != nil || data.ID != 42 || data.Type != 1 || data.Name != "demo" || data.Crt != cert || data.Key != key {
			t.Error("invalid UUSEC update")
		}
		io.WriteString(w, `"OK"`)
	})
	if _, err := d.Deploy(context.Background(), cert, key); err != nil || calls != 2 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestWestHostingDeploymentBranches(t *testing.T) {
	cert, key := testPair(t)
	for _, enabled := range []bool{false, true} {
		var cmds []string
		d := localDeployer(t, "westcn-vhost", map[string]any{"target": "site-ftp"}, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.URL.Path != "/vhost/" || r.ParseForm() != nil {
				t.Error("invalid West.cn POST")
				return
			}
			form := r.PostForm
			signature := md5.Sum([]byte("模拟demo-west" + form.Get("time")))
			if form.Get("username") != "模拟" || form.Get("token") != hex.EncodeToString(signature[:]) || form.Get("sitename") != "site-ftp" || form.Get("act") != "vhostssl" {
				t.Error("invalid West.cn parameters or signature")
			}
			cmd := form.Get("cmd")
			cmds = append(cmds, cmd)
			switch cmd {
			case "info":
				if len(cmds) == 1 {
					value := 0
					if enabled {
						value = 1
					}
					fmt.Fprintf(w, `{"result":"200","data":{"SSLEnabled":%d}}`, value)
				} else {
					io.WriteString(w, `{"result":200,"data":{"sslcert":{"ssl":{"one.example.test":{"sysid":4},"two.example.test":{"sysid":6},"not-covered.test":{"sysid":"2"}}}}}`)
				}
			case "import":
				if form.Get("keycontent") != key || form.Get("certcontent") != cert {
					t.Error("invalid certificate import")
				}
				io.WriteString(w, `{"result":200}`)
			case "openssl":
				io.WriteString(w, `{"result":200}`)
			case "clearsslcache":
				if form.Get("dm") != "one.example.test" || form.Get("sslid") != "4" {
					t.Error("incorrect site binding")
				}
				io.WriteString(w, `{"result":200}`)
			default:
				t.Error("unexpected West.cn command")
			}
		})
		_, err := d.Deploy(context.Background(), cert, key)
		want := []string{"info", "import", "openssl"}
		if enabled {
			want = []string{"info", "import", "info", "clearsslcache"}
		}
		if err != nil || !slices.Equal(cmds, want) {
			t.Fatalf("cmds=%v err=%v", cmds, err)
		}
	}
}

func TestDeploymentRejectsRedirectKeyMismatchAndInvalidID(t *testing.T) {
	cert, key := testPair(t)
	d := localDeployer(t, "xp", map[string]any{"target": "demo"}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/unexpected" {
			t.Error("followed credential-bearing redirect")
		}
		http.Redirect(w, r, "/unexpected", http.StatusTemporaryRedirect)
	})
	if _, err := d.Deploy(context.Background(), cert, key); err == nil {
		t.Error("accepted redirect")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Deploy(canceled, cert, key); !errors.Is(err, context.Canceled) {
		t.Error("ignored cancellation")
	}
	d = localDeployer(t, "lucky", nil, func(http.ResponseWriter, *http.Request) { t.Error("made request with invalid key pair") })
	_, otherKey := testPair(t)
	if _, err := d.Deploy(context.Background(), cert, otherKey); err == nil {
		t.Error("accepted mismatched key pair")
	}
	if _, err := New("uusec", map[string]any{"serverUrl": "https://example.test", "username": "demo", "password": "demo"}, map[string]any{"target": "99999999999999999999999", "name": "demo"}); err == nil {
		t.Error("accepted invalid numeric target")
	}
}
