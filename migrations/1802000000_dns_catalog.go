package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

// The account ID is also the access ID. DNS-01 graphs created before this
// migration keep their providerAccessId, and no access configuration is copied.
func init() {
	m.Register(func(app core.App) error {
		access, err := app.FindCollectionByNameOrId("access")
		if err != nil {
			return err
		}
		accounts := core.NewBaseCollection("dnsAccount")
		accounts.Fields.Add(
			&core.RelationField{Name: "accessRef", CollectionId: access.Id, Required: true, CascadeDelete: true, MaxSelect: 1},
			&core.BoolField{Name: "disabled"},
		)
		accounts.AddIndex("idx_dns_account_access", true, "accessRef", "")
		if err := app.Save(accounts); err != nil {
			return err
		}
		zones := core.NewBaseCollection("dnsZone")
		zones.Fields.Add(
			&core.RelationField{Name: "accountRef", CollectionId: accounts.Id, Required: true, CascadeDelete: true, MaxSelect: 1},
			&core.TextField{Name: "providerZoneId", Required: true, Max: 255},
			&core.TextField{Name: "name", Required: true, Max: 253},
			&core.TextField{Name: "status", Max: 128},
			&core.BoolField{Name: "present"},
			&core.JSONField{Name: "tags", MaxSize: 8192},
			&core.TextField{Name: "groupName", Max: 128},
			&core.TextField{Name: "notes", Max: 2048},
			&core.TextField{Name: "expiresOn", Max: 10},
			&core.BoolField{Name: "reminderEnabled"},
			&core.NumberField{Name: "reminderDays", OnlyInt: true},
			&core.RelationField{Name: "notificationRef", CollectionId: access.Id, MaxSelect: 1},
			&core.TextField{Name: "reminderSentFor", Max: 128},
			&core.TextField{Name: "reminderClaim", Max: 32},
			&core.NumberField{Name: "reminderClaimUntil", OnlyInt: true},
		)
		zones.AddIndex("idx_dns_zone_identity", true, "accountRef, providerZoneId", "")
		zones.AddIndex("idx_dns_zone_expiry", false, "expiresOn", "reminderEnabled=1")
		return app.Save(zones)
	}, func(app core.App) error {
		for _, name := range []string{"dnsZone", "dnsAccount"} {
			c, err := app.FindCollectionByNameOrId(name)
			if err != nil {
				return err
			}
			if err := app.Delete(c); err != nil {
				return err
			}
		}
		return nil
	})
}
