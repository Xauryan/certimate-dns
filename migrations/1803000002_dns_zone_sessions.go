package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		zones, err := app.FindCollectionByNameOrId("dnsZone")
		if err != nil {
			return err
		}
		zones.Fields.Add(&core.BoolField{Name: "quickLoginEnabled"})
		if err := app.Save(zones); err != nil {
			return err
		}
		s := core.NewAuthCollection("dns_zone_sessions")
		s.AuthRule = nil
		s.PasswordAuth.Enabled = false
		s.Fields.GetByName(core.FieldNameEmail).(*core.EmailField).Required = false
		s.Fields.Add(
			&core.RelationField{Name: "zone", CollectionId: zones.Id, CascadeDelete: true, Required: true, MaxSelect: 1},
			&core.BoolField{Name: "writable"},
			&core.TextField{Name: "issuerCollection", Required: true, Hidden: true},
			&core.TextField{Name: "issuer", Required: true, Hidden: true},
			&core.TextField{Name: "issuerStamp", Required: true, Hidden: true},
			&core.TextField{Name: "interfaceKey", Hidden: true},
			&core.TextField{Name: "ticketHash", Hidden: true},
			&core.NumberField{Name: "ticketUntil", Required: true, OnlyInt: true, Hidden: true},
			&core.NumberField{Name: "expiresAt", Required: true, OnlyInt: true, Hidden: true},
		)
		s.AddIndex("idx_dns_zone_ticket", true, "ticketHash", "ticketHash != ''")
		s.AddIndex("idx_dns_zone_session_expiry", false, "expiresAt", "")
		if err := app.Save(s); err != nil {
			return err
		}
		_, err = app.DB().NewQuery(`CREATE TRIGGER dns_zone_revoke_quick_login
			AFTER UPDATE OF quickLoginEnabled ON dnsZone WHEN old.quickLoginEnabled = 1 AND new.quickLoginEnabled = 0
			BEGIN DELETE FROM dns_zone_sessions WHERE zone = new.id; END`).Execute()
		return err
	}, func(app core.App) error {
		if _, err := app.DB().NewQuery("DROP TRIGGER IF EXISTS dns_zone_revoke_quick_login").Execute(); err != nil {
			return err
		}
		s, err := app.FindCollectionByNameOrId("dns_zone_sessions")
		if err != nil {
			return err
		}
		if err = app.Delete(s); err != nil {
			return err
		}
		zones, err := app.FindCollectionByNameOrId("dnsZone")
		if err != nil {
			return err
		}
		zones.Fields.RemoveByName("quickLoginEnabled")
		return app.Save(zones)
	})
}
