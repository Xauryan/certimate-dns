package dnsmigrate

import (
	"errors"
	"testing"

	_ "github.com/certimate-go/certimate/migrations"
	"github.com/pocketbase/pocketbase/core"
)

func TestPromoteMemberAndZonePermission(t *testing.T) {
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	t.Setenv("CERTIMATE_ADMIN_PASSWORD", "synthetic-migration-test")
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.ResetBootstrapState() })
	if err := app.RunAllMigrations(); err != nil {
		t.Fatal(err)
	}
	create := func(name string, fields map[string]any) *core.Record {
		t.Helper()
		collection, err := app.FindCollectionByNameOrId(name)
		if err != nil {
			t.Fatal(err)
		}
		r := core.NewRecord(collection)
		for k, value := range fields {
			r.Set(k, value)
		}
		if err := app.Save(r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	access := create("access", map[string]any{"name": "synthetic-account", "provider": "aliyun"})
	member := create("dns_members", map[string]any{"email": "fixture@example.test", "password": "synthetic-member-password"})
	m := Manifest{
		Version: Version, Schema: 1049, Timezone: "UTC", Source: "member-fixture",
		Accounts: []Account{{ID: 1, Provider: "aliyun"}},
		Zones:    []Zone{{ID: 1, AccountID: 1, Name: "first.example.test"}, {ID: 2, AccountID: 1, Name: "second.example.test"}},
		Related: []Related{
			{ID: 63, Kind: "user", State: 1},
			{ID: 34, Kind: "permission", ParentID: 63, Domain: "first.example.test"},
			{ID: 35, Kind: "permission", ParentID: 63, Domain: "second.example.test", RR: "www"},
			{ID: 36, Kind: "permission", ParentID: 63, Domain: "first.example.test"},
		},
	}
	b := Bindings{Version: Version, Source: m.Source, Accounts: map[int64]string{1: access.Id}}
	report, err := Apply(t.Context(), app, &m, b)
	if err != nil {
		t.Fatal(err)
	}
	zones := map[int64]string{}
	for _, item := range report.Items {
		if item.Kind == "domain" {
			zones[item.Legacy] = item.Target
		}
	}
	grantCount := func() int {
		t.Helper()
		var n int
		if err := app.DB().NewQuery("SELECT COUNT(*) FROM dns_zone_grants").Row(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if grantCount() != 0 {
		t.Fatal("inventory import created grants without consent")
	}
	user := Promotion{Kind: "user", LegacyID: 63, TargetID: member.Id, Confirm: true}
	permission := Promotion{Kind: "permission", LegacyID: 34, TargetID: zones[1], Role: "reader", Confirm: true}
	conflict := func(t *testing.T, bindings ...Promotion) {
		t.Helper()
		b.Promotions = bindings
		report, err := Plan(t.Context(), app.DB(), &m, b)
		if err != nil {
			t.Fatal(err)
		}
		if report.Conflicts == 0 {
			t.Fatal("invalid permission promotion accepted")
		}
	}
	t.Run("member must be mapped", func(t *testing.T) { conflict(t, permission) })
	t.Run("source zone must match", func(t *testing.T) {
		wrong := permission
		wrong.TargetID = zones[2]
		conflict(t, user, wrong)
	})
	t.Run("record restriction cannot become a zone grant", func(t *testing.T) {
		narrow := Promotion{Kind: "permission", LegacyID: 35, TargetID: zones[2], Role: "reader", Confirm: true}
		conflict(t, user, narrow)
	})
	t.Run("duplicate selections are rejected", func(t *testing.T) {
		duplicate := permission
		duplicate.LegacyID = 36
		conflict(t, user, permission, duplicate)
	})
	t.Run("disabled target receives no grant", func(t *testing.T) {
		member.Set("disabled", true)
		if err := app.Save(member); err != nil {
			t.Fatal(err)
		}
		conflict(t, user, permission)
		member.Set("disabled", false)
		if err := app.Save(member); err != nil {
			t.Fatal(err)
		}
	})
	b.Promotions = []Promotion{permission, user}
	report, err = Plan(t.Context(), app.DB(), &m, b)
	if err != nil || report.Conflicts != 0 || grantCount() != 0 {
		t.Fatalf("consented preview failed or wrote grants: %v", err)
	}
	if _, err = Apply(t.Context(), app, &m, b); err != nil {
		t.Fatal(err)
	}
	grants, err := app.FindAllRecords("dns_zone_grants")
	if err != nil || len(grants) != 1 || grants[0].GetString("member") != member.Id || grants[0].GetString("zone") != zones[1] || grants[0].GetString("role") != "reader" {
		t.Fatal("consented import did not create exactly the selected direct reader grant")
	}
	if _, err = Apply(t.Context(), app, &m, b); err != nil || grantCount() != 1 {
		t.Fatalf("idempotent grant import failed: %v", err)
	}
	grants[0].Set("role", "editor")
	if err := app.Save(grants[0]); err != nil {
		t.Fatal(err)
	}
	conflict(t, user, permission)
	if err := app.Delete(grants[0]); err != nil {
		t.Fatal(err)
	}
	if _, err = Apply(t.Context(), app, &m, b); !errors.Is(err, ErrConflict) || grantCount() != 0 {
		t.Fatal("replay recreated a revoked grant")
	}
	duplicate := permission
	duplicate.LegacyID = 36
	conflict(t, user, duplicate)
}
