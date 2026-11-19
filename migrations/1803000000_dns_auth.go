package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
	"github.com/pocketbase/pocketbase/tools/types"
)

func init() {
	m.Register(func(app core.App) error {
		zones, err := app.FindCollectionByNameOrId("dnsZone")
		if err != nil {
			return err
		}

		// The collection APIs stay locked to superusers. Members authenticate via
		// PocketBase's password endpoint and read only projected DNS API results.
		members := core.NewAuthCollection("dns_members")
		members.Fields.Add(&core.BoolField{Name: "disabled"}, &core.BoolField{Name: "apiEnabled"})
		members.AuthRule = types.Pointer("disabled = false")

		workspaces := core.NewBaseCollection("dns_workspaces")
		workspaces.Fields.Add(&core.TextField{Name: "name", Required: true, Max: 160})
		workspaces.AddIndex("idx_dns_workspace_name", true, "name", "")

		relation := func(name string, target *core.Collection) *core.RelationField {
			return &core.RelationField{Name: name, CollectionId: target.Id, Required: true, MaxSelect: 1, CascadeDelete: true}
		}
		workspaceZones := core.NewBaseCollection("dns_workspace_zones")
		workspaceZones.Fields.Add(relation("workspace", workspaces), relation("zone", zones))
		workspaceZones.AddIndex("idx_dns_workspace_zone", true, "workspace, zone", "")

		grant := func(name, field string, scope *core.Collection) *core.Collection {
			c := core.NewBaseCollection(name)
			c.Fields.Add(relation("member", members), relation(field, scope),
				&core.SelectField{Name: "role", Required: true, MaxSelect: 1, Values: []string{"reader", "editor"}})
			c.AddIndex("idx_"+name, true, "member, "+field, "")
			return c
		}
		for _, c := range []*core.Collection{
			members, workspaces, workspaceZones,
			grant("dns_workspace_grants", "workspace", workspaces),
			grant("dns_zone_grants", "zone", zones),
		} {
			if err := app.Save(c); err != nil {
				return err
			}
		}
		// Invalidating the signing key in the same transaction keeps previous
		// PocketBase sessions revoked even if the member is enabled again.
		if _, err = app.DB().NewQuery(`CREATE TRIGGER dns_member_disable_keys
			AFTER UPDATE OF apiEnabled ON dns_members WHEN old.apiEnabled = 1 AND new.apiEnabled = 0
			BEGIN DELETE FROM dns_interface_keys WHERE owner_collection = 'dns_members' AND owner = new.id; END`).Execute(); err != nil {
			return err
		}
		_, err = app.DB().NewQuery(`CREATE TRIGGER dns_member_disable_sessions
			AFTER UPDATE OF disabled ON dns_members WHEN old.disabled = 0 AND new.disabled = 1
			BEGIN UPDATE dns_members SET tokenKey = lower(hex(randomblob(24))) WHERE id = new.id; END`).Execute()
		return err
	}, func(app core.App) error {
		for _, name := range []string{"dns_zone_grants", "dns_workspace_grants", "dns_workspace_zones", "dns_workspaces", "dns_members"} {
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
