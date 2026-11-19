package dnsauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/domain"
	_ "github.com/certimate-go/certimate/migrations"
)

func setup(t *testing.T) *core.BaseApp {
	t.Helper()
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir(), EncryptionEnv: "CERTIMATE_DNS_TEST_ENCRYPTION"})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.ResetBootstrapState() })
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	return app
}

func save(t *testing.T, app core.App, collection string, fields map[string]any) *core.Record {
	t.Helper()
	c, err := app.FindCollectionByNameOrId(collection)
	if err != nil {
		t.Fatal(err)
	}
	r := core.NewRecord(c)
	for k, v := range fields {
		r.Set(k, v)
	}
	if err := app.Save(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func request(t *testing.T, handler http.Handler, method, url, token, body string) (int, string) {
	t.Helper()
	r := httptest.NewRequest(method, url, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", token)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

func TestMemberScopesAndSessionLifecycle(t *testing.T) {
	app := setup(t)
	member := save(t, app, dnsauth.Members, map[string]any{"email": "member@example.test", "password": "synthetic-test-password"})
	other := save(t, app, dnsauth.Members, map[string]any{"email": "other@example.test", "password": "synthetic-test-password"})
	const sentinel = "synthetic-config-sentinel"
	addAccount := func() string {
		a := save(t, app, "access", map[string]any{"name": "test account", "provider": "cloudflare", "config": map[string]string{"apiToken": sentinel}})
		return save(t, app, "dnsAccount", map[string]any{"id": a.Id, "accessRef": a.Id}).Id
	}
	a, b := addAccount(), addAccount()
	zone := func(account, upstream, name string) *core.Record {
		return save(t, app, "dnsZone", map[string]any{"accountRef": account, "providerZoneId": upstream, "name": name, "present": true, "notes": sentinel})
	}
	hidden := zone(b, "shared", "00-hidden.test")
	read := zone(a, "read", "01-reader.test")
	both := zone(a, "shared", "02-editor.test")
	ws := save(t, app, "dns_workspaces", map[string]any{"name": "one"})
	for _, z := range []*core.Record{read, both} {
		save(t, app, "dns_workspace_zones", map[string]any{"workspace": ws.Id, "zone": z.Id})
	}
	save(t, app, "dns_workspace_grants", map[string]any{"workspace": ws.Id, "member": member.Id, "role": "reader"})
	editor := save(t, app, "dns_zone_grants", map[string]any{"member": member.Id, "zone": both.Id, "role": "editor"})
	save(t, app, "dns_zone_grants", map[string]any{"member": other.Id, "zone": hidden.Id, "role": "editor"})

	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	dnsauth.Bind(router.Group("/api"))
	mux, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	login := func() (int, string) {
		return request(t, mux, "POST", "/api/collections/dns_members/auth-with-password", "", `{"identity":"member@example.test","password":"synthetic-test-password"}`)
	}
	status, payload := login()
	var session struct{ Token string }
	if err := json.Unmarshal([]byte(payload), &session); err != nil || session.Token == "" || status != 200 {
		t.Fatalf("valid member login failed (HTTP %d)", status)
	}
	token := session.Token
	checkPage := func(page int, suffix string, wantTotal int, wantID string, write bool) {
		t.Helper()
		status, body := request(t, mux, "GET", "/api/dns-member/zones?perPage=1&page="+suffix, token, "")
		var result struct {
			Code int
			Data struct {
				Total int
				Items []dnsauth.Zone
			}
		}
		if status != 200 || json.Unmarshal([]byte(body), &result) != nil || result.Code != 0 ||
			result.Data.Total != wantTotal || strings.Contains(body, sentinel) || strings.Contains(body, hidden.GetString("name")) {
			t.Fatalf("invalid scoped metadata page %d", page)
		}
		if wantID == "" {
			if len(result.Data.Items) != 0 {
				t.Fatal("expected empty page")
			}
		} else if len(result.Data.Items) != 1 || result.Data.Items[0].ID != wantID || result.Data.Items[0].CanWrite != write {
			t.Fatalf("incorrect zone or effective role on page %d", page)
		}
	}
	checkPage(1, "1", 2, read.Id, false)
	checkPage(2, "2", 2, both.Id, true)
	checkPage(3, "3", 2, "", false)
	for _, path := range []string{"/api/collections/access/records", "/api/collections/access/records/" + a, "/api/collections/dns_members/records",
		"/api/collections/dns_zone_grants/records", "/api/collections/dnsZone/records/" + read.Id, "/api/collections/certificate/records"} {
		if status, _ := request(t, mux, "GET", path, token, ""); status < 400 {
			t.Fatalf("raw collection unexpectedly accessible: %s", path)
		}
	}
	if status, _ := request(t, mux, "POST", "/api/collections/dns_zone_grants/records", token,
		`{"member":"`+member.Id+`","zone":"`+hidden.Id+`","role":"editor"}`); status < 400 {
		t.Fatal("member could create grant")
	}
	e := &core.RequestEvent{App: app, Auth: member}
	e.Request = httptest.NewRequest("GET", "/", nil)
	read.Set("hidden", true)
	if err := app.Save(read); err != nil {
		t.Fatal(err)
	}
	checkPage(1, "1", 1, both.Id, true)
	if _, err := dnsauth.GetZone(e, read.Id, false); err != nil {
		t.Fatal("hidden granted zone detail unavailable")
	}
	read.Set("hidden", false)
	if err := app.Save(read); err != nil {
		t.Fatal(err)
	}
	if err := dnsauth.RequireZone(e, "cloudflare", a, "shared", true); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		provider, account, zone string
		write                   bool
		code                    int
	}{
		{"aliyun", a, "shared", true, 404}, {"cloudflare", b, "shared", false, 404}, {"cloudflare", a, "read", true, 403},
	} {
		err, ok := dnsauth.RequireZone(e, tc.provider, tc.account, tc.zone, tc.write).(*domain.Error)
		if !ok || err.Code != tc.code {
			t.Fatalf("incorrect denial for %+v", tc)
		}
	}
	if _, err := dnsauth.GetZone(e, hidden.Id, false); !domain.IsRecordNotFoundError(err) {
		t.Fatal("local id lookup exposed another member's zone")
	}
	if err := app.Delete(editor); err != nil {
		t.Fatal(err)
	}
	checkPage(2, "2", 2, both.Id, false)
	both.Set("present", false)
	if err := app.Save(both); err != nil {
		t.Fatal(err)
	}
	checkPage(1, "1", 1, read.Id, false)
	account, err := app.FindRecordById("dnsAccount", a)
	if err != nil {
		t.Fatal(err)
	}
	account.Set("disabled", true)
	if err := app.Save(account); err != nil {
		t.Fatal(err)
	}
	checkPage(1, "1", 0, "", false)
	if err := dnsauth.RequireZone(e, "cloudflare", a, "read", false); !domain.IsRecordNotFoundError(err) {
		t.Fatal("disabled account allowed detail")
	}
	if status, _ := request(t, mux, "GET", "/api/dns-member/zones", "", ""); status != 401 {
		t.Fatalf("anonymous status=%d", status)
	}
	member.Set("disabled", true)
	if err := app.Save(member); err != nil {
		t.Fatal(err)
	}
	if status, _ := login(); status < 400 {
		t.Fatal("disabled member could log in")
	}
	member, err = app.FindRecordById(dnsauth.Members, member.Id)
	if err != nil {
		t.Fatal(err)
	}
	member.Set("disabled", false)
	if err := app.Save(member); err != nil {
		t.Fatal(err)
	}
	if status, _ := request(t, mux, "GET", "/api/dns-member/zones", token, ""); status != 401 {
		t.Fatalf("old session recovered after enable: status=%d", status)
	}
	if status, _ := login(); status != 200 {
		t.Fatal("re-enabled member unable to log in")
	}
}
