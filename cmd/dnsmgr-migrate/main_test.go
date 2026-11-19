package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/certimate-go/certimate/internal/dnsmigrate"
	_ "github.com/certimate-go/certimate/migrations"
	"github.com/pocketbase/pocketbase/core"
)

func TestImportLifecycle(t *testing.T) {
	dir := t.TempDir()
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: dir})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.ResetBootstrapState() })
	t.Setenv("CERTIMATE_ADMIN_PASSWORD", "synthetic-test-password")
	if err := app.RunAllMigrations(); err != nil {
		t.Fatal(err)
	}
	c, err := app.FindCollectionByNameOrId("access")
	if err != nil {
		t.Fatal(err)
	}
	access := core.NewRecord(c)
	access.Set("name", "synthetic")
	access.Set("provider", "aliyun")
	if err := app.Save(access); err != nil {
		t.Fatal(err)
	}
	m := dnsmigrate.Manifest{Version: 1, Schema: 1049, Timezone: "UTC", Source: "fixture", Accounts: []dnsmigrate.Account{{ID: 1, Provider: "aliyun"}}, Zones: []dnsmigrate.Zone{{ID: 2, AccountID: 1, Name: "example.test", Expires: "2030-06-01", Notice: true}}, Tasks: []dnsmigrate.Task{{ID: 3, ZoneID: 2, RR: "www", Record: "17", Active: true, Kind: "sctask", Schedule: &dnsmigrate.Schedule{Mode: 1, At: "02:42", Value: "edge.example.test"}}}, Related: []dnsmigrate.Related{{Kind: "user", ID: 1000, State: 1}}}
	path := filepath.Join(dir, "manifest.json")
	if err := publish(path, &m); err != nil {
		t.Fatal(err)
	}
	if err := publish(path, &m); err == nil {
		t.Fatal("replaced manifest")
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("manifest is not private")
	}
	bindings := filepath.Join(dir, "bindings.json")
	b, err := json.Marshal(dnsmigrate.Bindings{Version: 1, Source: "fixture", Accounts: map[int64]string{1: access.Id}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(bindings, b, 0600); err != nil {
		t.Fatal(err)
	}
	call := func(cmd string, conflict bool) dnsmigrate.Report {
		t.Helper()
		var out bytes.Buffer
		err := run(t.Context(), []string{cmd, "-dir", dir, "-bindings", bindings, "-in", path}, &out)
		if err != nil && !(conflict && errors.Is(err, dnsmigrate.ErrConflict)) || conflict && err == nil {
			t.Fatalf("%s: %v", cmd, err)
		}
		var r dnsmigrate.Report
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	count := func(table string) int {
		t.Helper()
		var n int
		if err := app.DB().NewQuery("SELECT count(*) FROM " + table).Row(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	plan := call("dry-run", false)
	if len(plan.Items) != 4 || plan.Items[2].Action != "draft" || plan.Items[3].Action != "stage" || count("dns_import_items") != 0 || count("dnsAccount") != 0 {
		t.Fatal("incorrect dry run")
	}
	// A failure after the catalog writes must roll back the entire import.
	if _, err := app.DB().NewQuery("CREATE TRIGGER synthetic_reject BEFORE INSERT ON dns_automation_tasks BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END").Execute(); err != nil {
		t.Fatal(err)
	}
	if err := run(t.Context(), []string{"import", "-dir", dir, "-bindings", bindings, "-in", path}, new(bytes.Buffer)); err == nil || count("dnsZone") != 0 || count("dnsAccount") != 0 || count("dns_import_items") != 0 {
		t.Fatal("failed import left inventory changes")
	}
	if _, err := app.DB().NewQuery("DROP TRIGGER synthetic_reject").Execute(); err != nil {
		t.Fatal(err)
	}
	applied := call("import", false)
	if count("dns_import_items") != 4 || count("dns_automation_tasks") != 1 || applied.Items[1].Target != plan.Items[1].Target {
		t.Fatal("incomplete import or changed mapping")
	}
	z, err := app.FindRecordById("dnsZone", plan.Items[1].Target)
	if err != nil || z.GetBool("present") || z.GetBool("reminderEnabled") || z.GetString("expiresOn") != "2030-06-01" {
		t.Fatal("unexpected imported zone state")
	}
	var state string
	if err := app.DB().NewQuery("SELECT state FROM dns_automation_tasks").Row(&state); err != nil || state != "draft" {
		t.Fatal("legacy task activated during import")
	}
	z.Set("notes", "after import")
	if err := app.Save(z); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB().NewQuery("UPDATE dns_automation_tasks SET state='paused'").Execute(); err != nil {
		t.Fatal(err)
	}
	for _, item := range call("import", false).Items {
		if item.Action != "unchanged" {
			t.Fatalf("replay changed %s", item.Kind)
		}
	}
	if err := app.DB().NewQuery("SELECT state FROM dns_automation_tasks").Row(&state); err != nil || state != "paused" {
		t.Fatal("replay touched edited task")
	}
	m.Zones[0].Expires = "2031-06-01"
	path = filepath.Join(dir, "changed.json")
	if err := publish(path, &m); err != nil {
		t.Fatal(err)
	}
	if r := call("import", true); r.Conflicts == 0 || count("dns_import_items") != 4 {
		t.Fatal("changed source did not conflict")
	}
	z, err = app.FindRecordById("dnsZone", plan.Items[1].Target)
	if err != nil || z.GetString("notes") != "after import" || z.GetString("expiresOn") != "2030-06-01" {
		t.Fatal("overwrote target metadata")
	}
}
