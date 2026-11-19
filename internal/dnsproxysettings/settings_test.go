package dnsproxysettings

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/certimate-go/certimate/migrations"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
)

func TestAdminProxySettings(t *testing.T) {
	t.Setenv("CERTIMATE_ADMIN_USERNAME", "proxy-admin@example.test")
	t.Setenv("CERTIMATE_ADMIN_PASSWORD", "fixture-proxy-admin-password")
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.ResetBootstrapState() })
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	a, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "proxy-admin@example.test")
	if err != nil {
		t.Fatal(err)
	}
	token, err := a.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	col, err := app.FindCollectionByNameOrId("dns_members")
	if err != nil {
		t.Fatal(err)
	}
	member := core.NewRecord(col)
	member.SetEmail("proxy-member@example.test")
	member.SetPassword("fixture-proxy-member-password")
	if err := app.Save(member); err != nil {
		t.Fatal(err)
	}
	memberToken, err := member.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	status := 200
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Host != "dl.amh.sh" || r.URL.RequestURI() != "/ip.htm" || r.Header.Get("Authorization") != "" {
			t.Error("unexpected probe target or authentication")
		}
		calls++
		w.WriteHeader(status)
	}))
	defer remote.Close()
	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	const user = "synthetic-proxy-user"
	const password = "synthetic-proxy-password"
	Bind(router.Group("/api"), func(u *url.URL) (*http.Transport, error) {
		pwd, _ := u.User.Password()
		if u.Host != "proxy.example.test:1080" || u.User.Username() != user || pwd != password {
			t.Fatal("incorrect saved proxy credentials")
		}
		pool := x509.NewCertPool()
		pool.AddCert(remote.Certificate())
		return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, network, remote.Listener.Addr().String())
		}}, nil
	})
	handler, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, actor, body string, want int) map[string]any {
		t.Helper()
		r := httptest.NewRequest(method, "/api/dns-proxy/"+path, strings.NewReader(body))
		r.Header.Set("Authorization", actor)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s returned %d want %d", method, path, w.Code, want)
		}
		data := w.Body.String()
		if strings.Contains(data, password) || strings.Contains(data, user) {
			t.Fatal("exposed proxy credentials")
		}
		var m map[string]any
		if data != "" {
			if err := json.Unmarshal([]byte(data), &m); err != nil {
				t.Fatal(err)
			}
		}
		return m
	}
	for _, r := range []struct{ method, path string }{{"GET", "settings"}, {"PUT", "settings"}, {"POST", "test"}} {
		request(r.method, r.path, "", "{}", 401)
		request(r.method, r.path, memberToken, "{}", 403)
	}
	request("POST", "test", token, "{}", 400)
	request("PUT", "settings", token, `{"enabled":true,"server":"socks5h://proxy.example.test:1080","username":"`+user+`","password":"`+password+`"}`, 204)
	got := request("GET", "settings", token, "", 200)
	if got["server"] != "socks5h://proxy.example.test:1080" || got["hasPassword"] != true || got["enabled"] != true || got["configured"] != true {
		t.Fatal("missing status flags")
	}
	r, err := read(app)
	if err != nil || r.Credentials == "" || strings.Contains(r.Credentials, password) {
		t.Fatal("proxy credentials not sealed")
	}
	key, err := os.Stat(filepath.Join(app.DataDir(), ".dns-proxy.key"))
	if err != nil || key.Mode().Perm()&0077 != 0 {
		t.Fatal("expected private keyfile")
	}
	if u, err := LoadURL(app); err != nil || u.User.Username() != user {
		t.Fatal("saved proxy unavailable")
	}
	request("POST", "test", token, `{"url":"https://other.example.test"}`, 400)
	if calls != 0 {
		t.Fatal("arbitrary probe destination accepted")
	}
	request("PUT", "settings", token, `{"enabled":false}`, 204)
	if u, err := LoadURL(app); err != nil || u != nil {
		t.Fatal("disabled proxy still active")
	}
	request("POST", "test", token, "{}", 200)
	status = 403
	request("POST", "test", token, "{}", 502)
	if calls != 2 {
		t.Fatal("unexpected number of probe requests")
	}
	request("PUT", "settings", token, `{"enabled":true,"server":"http://new.example.test:9090"}`, 204)
	u, err := LoadURL(app)
	if err != nil || u == nil || u.User != nil {
		t.Fatal("credentials carried onto new endpoint")
	}
	request("PUT", "settings", token, `{"enabled":false,"server":""}`, 204)
	if got := request("GET", "settings", token, "", 200); got["configured"] != false || got["hasUsername"] != false {
		t.Fatal("credentials not cleared")
	}
}

func TestProxyEndpointSyntax(t *testing.T) {
	for _, bad := range []string{"https://user@host.test:443", "https://host.test:443/path", "http://host.test:8080?token=x", "https://host.test", "socks4a://host.test:80", "http://host.test:65536", "http://host..test:80", "https://host.test:443#"} {
		if _, err := parseServer(bad); err == nil {
			t.Fatal("accepted invalid proxy endpoint")
		}
	}
	for _, good := range []string{"http://127.0.0.1:8080", "https://proxy.test:443", "socks4://[::1]:1080", "socks5://localhost:1080", "socks5h://proxy.test:12345"} {
		if _, err := parseServer(good); err != nil {
			t.Fatal(err)
		}
	}
}
