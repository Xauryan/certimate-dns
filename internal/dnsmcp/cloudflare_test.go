package dnsmcp

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"

	"github.com/certimate-go/certimate/internal/dnsauth"
	_ "github.com/certimate-go/certimate/migrations"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	cf "github.com/certimate-go/certimate/pkg/sdk3rd/cloudflare"
)

func TestCloudflareKeyBoundaries(t *testing.T) {
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.ResetBootstrapState() })
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	save := func(name string, data object) *core.Record {
		c, err := app.FindCollectionByNameOrId(name)
		if err != nil {
			t.Fatal(err)
		}
		r := core.NewRecord(c)
		for k, v := range data {
			r.Set(k, v)
		}
		if err := app.Save(r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	account := func(name string) *core.Record {
		a := save("access", object{"name": name, "provider": "cloudflare", "config": object{"apiToken": "synthetic", "accountId": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}})
		return save("dnsAccount", object{"id": a.Id, "accessRef": a.Id})
	}
	one, other := account("one"), account("other")
	zone := func(a *core.Record, name, id string) *core.Record {
		return save("dnsZone", object{"accountRef": a.Id, "name": name, "providerZoneId": id, "present": true})
	}
	parent := zone(one, "example.test", "provider-parent")
	child := zone(one, "private.example.test", "provider-child")
	foreign := zone(other, "private.example.test", "provider-child")
	admin := save(core.CollectionNameSuperusers, object{"email": "admin@example.test", "password": "synthetic-test-password"})
	member := save(dnsauth.Members, object{"email": "member@example.test", "password": "synthetic-test-password"})
	e := &core.RequestEvent{App: app, Auth: admin, Event: router.Event{Request: httptest.NewRequest("POST", "/mcp", nil), Response: httptest.NewRecorder()}}
	grant := scope{Zones: []string{parent.Id, foreign.Id}}
	resolveCalls := 0
	s := service{resolve: func(ctx context.Context, provider, id string, discovery bool) (dns.Provider, error) {
		resolveCalls++
		return nil, nil
	}}
	if _, p := s.executeCF(e, "cf_tunnel_query", "list", object{"account_id": one.Id}, grant); p != denied || resolveCalls != 0 {
		t.Fatal("a zone grant cannot enumerate account tunnels")
	}
	if _, p := s.executeCF(e, "cf_hostname_query", "list", object{"domain_id": child.Id}, grant); p != missing || resolveCalls != 0 {
		t.Fatal("an account's other zones must not be visible")
	}
	z, p := cfPublishedZone(e, grant, one.Id, "ok.example.test", true)
	if p != nil || z.ID != parent.Id {
		t.Fatal("granted hostname did not resolve to its own zone")
	}
	if _, p := cfPublishedZone(e, grant, one.Id, "host.private.example.test", true); p != missing {
		t.Fatal("a parent zone or an overlapping name on another account authorized a child")
	}
	if _, p := cfPublishedZone(e, grant, one.Id, "notexample.test", true); p != missing {
		t.Fatal("wrong boundary matched zone suffix")
	}
	if bound, p := s.cfAccount(e, nil, one.Id, grant, object{}); p != nil || bound != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatal("could not resolve bound provider account")
	}
	if _, p := s.cfAccount(e, nil, one.Id, grant, object{"domain_id": foreign.Id}); p != missing || resolveCalls != 0 {
		t.Fatal("cross-account zone ID reached resolver")
	}
	out, p := s.executeCF(e, "cf_hostname_query", "txt_targets", object{"domain_id": parent.Id, "hostname": "_dcv.example.test"}, grant)
	if p != nil || resolveCalls != 0 {
		t.Fatal("TXT target discovery should be local")
	}
	rows := out["data"].(object)["candidates"].([]object)
	if len(rows) != 1 || rows[0]["domain_id"] != parent.Id || rows[0]["record_name"] != "_dcv" {
		t.Fatal("unexpected TXT targets")
	}
	e.Auth = member
	if _, p := s.executeCF(e, "cf_hostname_query", "txt_targets", object{"domain_id": parent.Id, "hostname": "example.test"}, grant); p != denied {
		t.Fatal("Cloudflare tools require administrator role")
	}
	e.Auth = admin
	one.Set("disabled", true)
	if err := app.Save(one); err != nil {
		t.Fatal(err)
	}
	if _, p := s.executeCF(e, "cf_hostname_query", "list", object{"domain_id": parent.Id}, grant); p != missing || resolveCalls != 0 {
		t.Fatal("disabled account reached resolver")
	}
}

func TestCloudflareListContract(t *testing.T) {
	ctx := context.Background()
	const total = cf.DNSPageSize + 3
	calls := 0
	fetch := func(ctx context.Context, p int) (*cf.DNSPage[int], error) {
		calls++
		start := (p - 1) * cf.DNSPageSize
		rows := []int{}
		for i := start; i < min(start+cf.DNSPageSize, total); i++ {
			rows = append(rows, i)
		}
		return &cf.DNSPage[int]{Items: rows, Info: cf.PageInfo{Page: p, Total: total}}, nil
	}
	out, p := cfList(ctx, nil, fetch)
	if p != nil || calls != 2 || out["total"] != total || len(out["rows"].([]int)) != total {
		t.Fatal("default list lost results")
	}
	out, p = cfList(ctx, object{"page": "2"}, fetch)
	if p != nil || calls != 3 || out["total"] != total || len(out["rows"].([]int)) != 3 {
		t.Fatal("page selection failed")
	}
	if _, p := cfList(ctx, nil, func(context.Context, int) (*cf.DNSPage[int], error) {
		return &cf.DNSPage[int]{Info: cf.PageInfo{Page: 1, Total: total}}, nil
	}); p != upstream {
		t.Fatal("accepted incomplete response as complete")
	}
}

func TestCloudflareActionInventory(t *testing.T) {
	want := map[string]int{"cf_hostname_query": 4, "cf_hostname_manage": 9, "cf_tunnel_query": 5, "cf_tunnel_manage": 8}
	for _, tool := range cfTools {
		if want[tool.name] != len(tool.methods) {
			t.Errorf("%s inventory mismatch", tool.name)
		}
		delete(want, tool.name)
		for _, op := range tool.methods {
			if op.name == "token" && op.permission != "cf.tunnel.token.read" {
				t.Error("token uses generic read permission")
			}
			if strings.HasSuffix(tool.name, "_manage") && !isWrite(op.permission) {
				t.Errorf("write permission mislabeled read: %s", op.name)
			}
		}
	}
	if len(want) > 0 {
		t.Error("missing tools", want)
	}
}
