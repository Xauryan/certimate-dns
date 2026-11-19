package settings

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/certimate-go/certimate/migrations"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
)

func TestSiteAppearancePermissionsAndPersistence(t *testing.T) {
	t.Setenv("CERTIMATE_ADMIN_USERNAME", "appearance-admin@example.test")
	t.Setenv("CERTIMATE_ADMIN_PASSWORD", "fixture-appearance-admin-password")
	dir := t.TempDir()

	open := func() (core.App, http.Handler) {
		t.Helper()
		app := core.NewBaseApp(core.BaseAppConfig{DataDir: dir})
		if err := app.Bootstrap(); err != nil {
			t.Fatal(err)
		}
		if err := app.RunAppMigrations(); err != nil {
			t.Fatal(err)
		}
		router, err := apis.NewRouter(app)
		if err != nil {
			t.Fatal(err)
		}
		BindAppearance(router.Group("/api"))
		mux, err := router.BuildMux()
		if err != nil {
			t.Fatal(err)
		}
		return app, mux
	}

	app, mux := open()
	t.Cleanup(func() { _ = app.ResetBootstrapState() })
	admin, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "appearance-admin@example.test")
	if err != nil {
		t.Fatal(err)
	}
	adminToken, err := admin.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	collection, err := app.FindCollectionByNameOrId("dns_members")
	if err != nil {
		t.Fatal(err)
	}
	member := core.NewRecord(collection)
	member.SetEmail("appearance-member@example.test")
	member.SetPassword("fixture-appearance-member-password")
	if err := app.Save(member); err != nil {
		t.Fatal(err)
	}
	memberToken, err := member.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}

	request := func(method, token, body string, status int, response string) {
		t.Helper()
		r := httptest.NewRequest(method, "/api/appearance", strings.NewReader(body))
		r.Header.Set("Authorization", token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s returned %d, want %d: %s", method, w.Code, status, w.Body)
		}
		if response != "" && strings.TrimSpace(w.Body.String()) != response {
			t.Fatalf("%s returned %s, want %s", method, w.Body, response)
		}
		if method == http.MethodGet && w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("expected a non-cacheable public theme response")
		}
	}

	request(http.MethodGet, "", "", 200, `{"theme":"dark"}`)
	request(http.MethodPut, "", `{"theme":"light"}`, 401, "")
	request(http.MethodPut, memberToken, `{"theme":"light"}`, 403, "")
	request(http.MethodPut, adminToken, `{"theme":"skin-blue"}`, 400, "")
	request(http.MethodPut, adminToken, `{"theme":"light","css":"fixture-extra-field"}`, 200, `{"theme":"light"}`)
	request(http.MethodGet, memberToken, "", 200, `{"theme":"light"}`)
	request(http.MethodPut, adminToken, `{"theme":"system"}`, 200, `{"theme":"system"}`)

	if err := app.ResetBootstrapState(); err != nil {
		t.Fatal(err)
	}
	app, mux = open()
	request(http.MethodGet, "", "", 200, `{"theme":"system"}`)
}
