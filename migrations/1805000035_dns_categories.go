package migrations

import (
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		c := core.NewBaseCollection("dnsCategory")
		c.Fields.Add(
			&core.TextField{Name: "name", Required: true, Max: 128},
			&core.TextField{Name: "remark", Max: 100},
			&core.NumberField{Name: "sort", OnlyInt: true},
		)
		c.AddIndex("idx_dns_category_name", true, "name", "")
		if err := app.Save(c); err != nil {
			return err
		}
		zones, err := app.FindCollectionByNameOrId("dnsZone")
		if err != nil {
			return err
		}
		zones.Fields.Add(&core.RelationField{Name: "categoryRef", CollectionId: c.Id, MaxSelect: 1})
		zones.AddIndex("idx_dns_zone_category", false, "categoryRef", "")
		if err := app.Save(zones); err != nil {
			return err
		}
		// Keep the existing group names and give each distinct group a stable ID.
		var names []string
		if err := app.DB().NewQuery("SELECT DISTINCT groupName FROM dnsZone WHERE groupName <> ''").Column(&names); err != nil {
			return err
		}
		for _, name := range names {
			r := core.NewRecord(c)
			r.Set("name", name)
			if err := app.Save(r); err != nil {
				return err
			}
			if _, err := app.DB().NewQuery("UPDATE dnsZone SET categoryRef={:id} WHERE groupName={:name}").
				Bind(dbx.Params{"id": r.Id, "name": name}).Execute(); err != nil {
				return err
			}
		}
		return nil
	}, func(app core.App) error {
		zones, err := app.FindCollectionByNameOrId("dnsZone")
		if err != nil {
			return err
		}
		zones.RemoveIndex("idx_dns_zone_category")
		zones.Fields.RemoveByName("categoryRef")
		if err := app.Save(zones); err != nil {
			return err
		}
		c, err := app.FindCollectionByNameOrId("dnsCategory")
		if err != nil {
			return err
		}
		return app.Delete(c)
	})
}
