package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		a, err := app.FindCollectionByNameOrId("dnsAccount")
		if err != nil {
			return err
		}
		a.Fields.Add(&core.TextField{Name: "notes", Max: 2048})
		if err := app.Save(a); err != nil {
			return err
		}
		z, err := app.FindCollectionByNameOrId("dnsZone")
		if err != nil {
			return err
		}
		z.Fields.Add(&core.BoolField{Name: "hidden"}, &core.TextField{Name: "registeredOn", Max: 10}, &core.TextField{Name: "registrationStatus", Max: 16}, &core.TextField{Name: "registrationChecked", Max: 40}, &core.BoolField{Name: "autoRefresh"})
		if err := app.Save(z); err != nil {
			return err
		}
		// Reusing the same access ID for a different provider could grant a member
		// access to an unrelated zone whose provider-side identifier happens to match.
		_, err = app.DB().NewQuery(`CREATE TRIGGER dns_account_provider_guard BEFORE UPDATE OF provider ON access
 WHEN NEW.provider<>OLD.provider AND EXISTS(SELECT 1 FROM dnsZone WHERE accountRef=OLD.id)
 BEGIN SELECT RAISE(ABORT,'DNS zones are still linked to this account'); END`).Execute()
		return err
	}, func(app core.App) error {
		a, err := app.FindCollectionByNameOrId("dnsAccount")
		if err != nil {
			return err
		}
		a.Fields.RemoveByName("notes")
		if err := app.Save(a); err != nil {
			return err
		}
		if _, err := app.DB().NewQuery("DROP TRIGGER IF EXISTS dns_account_provider_guard").Execute(); err != nil {
			return err
		}
		z, err := app.FindCollectionByNameOrId("dnsZone")
		if err != nil {
			return err
		}
		for _, k := range []string{"hidden", "registeredOn", "registrationStatus", "registrationChecked", "autoRefresh"} {
			z.Fields.RemoveByName(k)
		}
		return app.Save(z)
	})
}
