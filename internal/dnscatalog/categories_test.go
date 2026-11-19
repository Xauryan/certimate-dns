package dnscatalog_test

import (
	"errors"
	"testing"

	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnscatalog"
	"github.com/certimate-go/certimate/internal/domain"
	_ "github.com/certimate-go/certimate/migrations"
)

func TestCategoryUpgradeAndManagement(t *testing.T) {
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.ResetBootstrapState() })

	zones := core.NewBaseCollection("dnsZone")
	zones.Fields.Add(&core.TextField{Name: "groupName", Max: 128})
	if err := app.Save(zones); err != nil {
		t.Fatal(err)
	}
	zone := func(group string) string {
		r := core.NewRecord(zones)
		r.Set("groupName", group)
		if err := app.Save(r); err != nil {
			t.Fatal(err)
		}
		return r.Id
	}
	first, second, other := zone("Imported group"), zone("Imported group"), zone("")
	var migration *core.Migration
	for _, v := range core.AppMigrations.Items() {
		if v.File == "1805000035_dns_categories.go" {
			migration = v
			break
		}
	}
	if migration == nil {
		t.Fatal("unregistered category migration")
	}
	if err := app.RunInTransaction(migration.Up); err != nil {
		t.Fatal(err)
	}
	categories, err := dnscatalog.ListCategories(app)
	if err != nil || len(categories) != 1 || categories[0].Name != "Imported group" || categories[0].DomainCount != 2 {
		t.Fatalf("category migration: %#v, %v", categories, err)
	}
	imported := categories[0].ID
	check := func(id, group, category string) {
		t.Helper()
		r, err := app.FindRecordById("dnsZone", id)
		if err != nil {
			t.Fatal(err)
		}
		if r.GetString("categoryRef") != category || r.GetString("groupName") != group {
			t.Fatalf("zone %s has category %s and group %s", id, r.GetString("categoryRef"), r.GetString("groupName"))
		}
	}
	check(first, "Imported group", imported)
	check(second, "Imported group", imported)
	check(other, "", "")

	name, remark, sortOrder := "Production", "Renew before launch", -10
	created, err := dnscatalog.SaveCategory(app, "", dnscatalog.CategoryPatch{Name: &name, Remark: &remark, Sort: &sortOrder})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = dnscatalog.SaveCategory(app, "", dnscatalog.CategoryPatch{Name: &name}); err == nil {
		t.Fatal("duplicate name accepted")
	}
	if err = dnscatalog.AssignCategory(app, []string{first, "missing-zone"}, created.ID); !errors.Is(err, domain.ErrRecordNotFound) {
		t.Fatalf("missing zone: %v", err)
	}
	check(first, "Imported group", imported)
	if err = dnscatalog.AssignCategory(app, []string{first, other}, created.ID); err != nil {
		t.Fatal(err)
	}
	if err = dnscatalog.DeleteCategory(app, created.ID); err == nil {
		t.Fatal("removed assigned category")
	}
	newName := "Production targets"
	updated, err := dnscatalog.SaveCategory(app, created.ID, dnscatalog.CategoryPatch{Name: &newName})
	if err != nil || updated.Remark != remark || updated.Sort != sortOrder || updated.DomainCount != 2 {
		t.Fatalf("partial rename: %#v, %v", updated, err)
	}
	check(first, newName, created.ID)
	check(other, newName, created.ID)
	categories, err = dnscatalog.ListCategories(app)
	if err != nil || len(categories) != 2 || categories[0].ID != created.ID {
		t.Fatalf("category ordering: %#v, %v", categories, err)
	}
	if err = dnscatalog.AssignCategory(app, []string{first, other}, ""); err != nil {
		t.Fatal(err)
	}
	check(first, "", "")
	if err = dnscatalog.DeleteCategory(app, created.ID); err != nil {
		t.Fatal(err)
	}

	if err = app.RunInTransaction(migration.Down); err != nil {
		t.Fatal(err)
	}
	r, err := app.FindRecordById("dnsZone", second)
	if err != nil || r.GetString("groupName") != "Imported group" {
		t.Fatalf("downgrade lost original group: %v", err)
	}
}
