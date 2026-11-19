package cfmanagement

import (
	"context"
	"encoding/json"
	"github.com/certimate-go/certimate/internal/domain"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
)

func TestCloudflareScopeBeforeLookupAndTXTTargets(t *testing.T) {
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.ResetBootstrapState() })
	api, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	Bind(api.Group("/api"), nil)
	mux, err := api.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []struct{ method, path string }{
		{"GET", "/accounts"}, {"POST", "/accounts/account/tunnels/tunnel/connector"}, {"DELETE", "/zones/zone/hostnames/hostname"},
	} {
		req := httptest.NewRequest(route.method, "/api/cloudflare/access"+route.path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != 401 && w.Code != 403 {
			t.Fatalf("unprotected Cloudflare route %s: %d", route.path, w.Code)
		}
	}
	_, err = app.DB().NewQuery(`
    CREATE TABLE access(id TEXT, name TEXT, provider TEXT, deleted TEXT);
    CREATE TABLE dnsAccount(id TEXT, accessRef TEXT, disabled INTEGER);
    CREATE TABLE dnsZone(providerZoneId TEXT, name TEXT, accountRef TEXT, present INTEGER);
    INSERT INTO access VALUES ('a','active','cloudflare',''),('b','another','aliyun',''),('c','disabled','cloudflare','');
    INSERT INTO dnsAccount VALUES ('a','a',0),('b','b',0),('c','c',1);
    INSERT INTO dnsZone VALUES ('z0','example.test','a',1),('z1','child.example.test','a',1),('z2','child.example.test','b',1),
    ('z3','_acme-challenge.child.example.test','c',1),('z4','_acme-challenge.child.example.test','a',0);
    `).Execute()
	if err != nil {
		t.Fatal(err)
	}
	e := &core.RequestEvent{App: app}
	e.Request = httptest.NewRequest("GET", "/", nil)
	if _, err := targetZones(e, "_acme-challenge.child.example.test"); err == nil {
		t.Fatal("anonymous target lookup permitted")
	}
	admins, err := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		t.Fatal(err)
	}
	e.Auth = core.NewRecord(admins)
	rows, err := targetZones(e, "_acme-challenge.Child.Example.Test.")
	if err != nil || len(rows) != 2 {
		t.Fatalf("target lookup: %v, rows: %d", err, len(rows))
	}
	for _, row := range rows {
		if row.Zone != "child.example.test" || row.Owner != "_acme-challenge" || row.AccessID == "c" {
			t.Fatalf("incorrect verification target: %+v", row)
		}
	}
	rows, err = targetZones(e, "notexample.test")
	if err != nil || len(rows) != 0 {
		t.Fatal("matched partial DNS label")
	}
}

type accessFixture struct{ a *domain.Access }

func (f accessFixture) GetById(context.Context, string) (*domain.Access, error) { return f.a, nil }

type selectedTransport func(*http.Request) (*http.Response, error)

func (f selectedTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The custom https scheme is installed on this account's transport only;
// both credential paths are exercised entirely in-process.
func TestSelectedTransportForPinnedZoneAndSaaS(t *testing.T) {
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.ResetBootstrapState() })
	_, err := app.DB().NewQuery(`CREATE TABLE access(id TEXT,name TEXT,provider TEXT,deleted TEXT,reserve TEXT);
      CREATE TABLE dnsAccount(id TEXT,accessRef TEXT,disabled INTEGER,notes TEXT);
      CREATE TABLE dnsZone(accountRef TEXT);
      INSERT INTO access VALUES('a','test','cloudflare','','');`).Execute()
	if err != nil {
		t.Fatal(err)
	}
	const account = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const zone = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	zoneAccount := account
	var checks, lists int
	tr := &http.Transport{}
	tr.RegisterProtocol("https", selectedTransport(func(r *http.Request) (*http.Response, error) {
		result := "[]"
		switch r.URL.Path {
		case "/client/v4/zones/" + zone:
			checks++
			if r.Header.Get("Authorization") != "Bearer synthetic-zone" {
				t.Fatal("incorrect zone read credential")
			}
			result = `{"name":"example.test","id":"` + zone + `","account":{"id":"` + zoneAccount + `"}}`
		case "/client/v4/zones/" + zone + "/custom_hostnames":
			lists++
			if r.Header.Get("Authorization") != "Bearer synthetic-main" {
				t.Fatal("incorrect management credential")
			}
		default:
			t.Fatalf("unexpected provider path: %s", r.URL.Path)
		}
		return &http.Response{Request: r, StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"success":true,"result":` + result + `}`))}, nil
	}))
	a := &domain.Access{Provider: "cloudflare", Config: map[string]any{"apiToken": "synthetic-main", "apiTokenForZone": "synthetic-zone", "accountId": account}, DNSManagementTransport: tr}
	run := func() int {
		t.Helper()
		e := &core.RequestEvent{App: app}
		e.Request = httptest.NewRequest("GET", "/", nil)
		e.Request.SetPathValue("access", "a")
		e.Request.SetPathValue("zone", zone)
		w := httptest.NewRecorder()
		e.Response = w
		err := withAccess(accessFixture{a}, func(op operation, _ *core.RequestEvent) (any, error) { return op.Hostnames(op.ctx, op.zone, op.page) })(e)
		var res struct{ Code int }
		if err != nil || json.Unmarshal(w.Body.Bytes(), &res) != nil {
			t.Fatal("invalid management response")
		}
		return res.Code
	}
	if run() != 0 || checks != 1 || lists != 1 {
		t.Fatal("selected transport did not serve both contexts")
	}
	zoneAccount = zone
	if run() == 0 || checks != 2 || lists != 1 {
		t.Fatal("foreign zone reached management operation")
	}
	a.Config["dnsManagementProxy"] = true
	if run() == 0 || checks != 2 || lists != 1 {
		t.Fatal("unavailable configured proxy must stop before provider access")
	}
}
