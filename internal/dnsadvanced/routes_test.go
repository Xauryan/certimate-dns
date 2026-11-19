package dnsadvanced

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/dnsauth"
	_ "github.com/certimate-go/certimate/migrations"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
)

type aliasFixture struct {
	dns.Provider
	added []string
}

func (*aliasFixture) DNSRecords(_ context.Context, _ string, page int, _ string) (*dns.DNSPage[dns.DNSRecord], error) {
	return &dns.DNSPage[dns.DNSRecord]{Info: dns.PageInfo{Page: page, Total: 1}, Items: []dns.DNSRecord{{ID: "provider-id", Name: "outside.example", Type: "TXT", Content: "synthetic"}}}, nil
}
func (*aliasFixture) DomainAliases(context.Context, string) ([]dns.DomainAlias, error) {
	return []dns.DomainAlias{{ID: "123", Name: "alias.example"}}, nil
}
func (f *aliasFixture) AddDomainAlias(_ context.Context, zone, alias string) error {
	f.added = append(f.added, zone+"/"+alias)
	return nil
}
func (*aliasFixture) DeleteDomainAlias(context.Context, string, string) error {
	panic("unexpected delete")
}

func TestRoutesAuthorizeBeforeResolvingAndWriting(t *testing.T) {
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.ResetBootstrapState() })
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	save := func(name string, fields map[string]any) *core.Record {
		t.Helper()
		col, err := app.FindCollectionByNameOrId(name)
		if err != nil {
			t.Fatal(err)
		}
		rec := core.NewRecord(col)
		for k, v := range fields {
			rec.Set(k, v)
		}
		if err := app.Save(rec); err != nil {
			t.Fatal(err)
		}
		return rec
	}
	m := save(dnsauth.Members, map[string]any{"email": "reader@example.test", "password": "test-only-member-password"})
	token, err := m.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	a := save("access", map[string]any{"name": "test account", "provider": "tencentcloud", "config": map[string]any{}})
	_ = save("dnsAccount", map[string]any{"id": a.Id, "accessRef": a.Id})
	z := save("dnsZone", map[string]any{"accountRef": a.Id, "providerZoneId": "example.org", "name": "example.org", "present": true})
	grant := save("dns_zone_grants", map[string]any{"member": m.Id, "zone": z.Id, "role": "reader"})
	r, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	p := &aliasFixture{}
	resolveCalls := 0
	Bind(r.Group("/api"), func(_ context.Context, provider, access string, zones bool) (dns.Provider, error) {
		resolveCalls++
		if provider != "tencentcloud" || access != a.Id || zones {
			t.Fatal("unexpected resolver scope")
		}
		return p, nil
	})
	mux, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	req := func(method, path, auth, body string, wantCode, wantResolve int) {
		t.Helper()
		request := httptest.NewRequest(method, "/api/dns/tencentcloud/"+a.Id+"/zones/"+path, strings.NewReader(body))
		request.Header.Set("Authorization", auth)
		request.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, request)
		var out struct {
			Code int `json:"code"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.Code != wantCode || resolveCalls != wantResolve {
			t.Fatalf("%s %s: code=%d resolve=%d", method, path, out.Code, resolveCalls)
		}
	}
	req("GET", "example.org/advanced/features", "", "", 401, 0)
	req("GET", "outside.org/advanced/features", token, "", 404, 0)
	req("POST", "example.org/advanced/aliases", token, `{"name":"alias.example"}`, 403, 0)
	req("GET", "example.org/advanced/aliases", token, "", 0, 1)
	req("GET", "example.org/advanced/records/missing/check", token, "", 404, 2)
	req("GET", "example.org/advanced/records/provider-id/check", token, "", 400, 3)
	grant.Set("role", "editor")
	if err := app.Save(grant); err != nil {
		t.Fatal(err)
	}
	req("POST", "example.org/advanced/aliases", token, `{"name":"alias.example","account":"other"}`, 400, 4)
	req("POST", "example.org/advanced/aliases", token, `{"name":"alias.example"}`, 0, 5)
	if len(p.added) != 1 || p.added[0] != "example.org/alias.example" {
		t.Fatal("incorrect write")
	}
	if err := app.Delete(grant); err != nil {
		t.Fatal(err)
	}
	req("DELETE", "example.org/advanced/aliases/123", token, "", 404, 5)
}
