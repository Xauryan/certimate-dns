package dnsmcp

import (
	"strconv"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

// DNSMgr persists numeric local IDs. Keep its wire identity stable across restarts and resynchronization.
func localZoneID(e *core.RequestEvent, id string) string {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n <= 0 || strconv.FormatInt(n, 10) != id {
		return id
	}
	var zone string
	err = e.App.DB().NewQuery("SELECT zone FROM dns_interface_zones WHERE id={:id}").Bind(dbx.Params{"id": n}).WithContext(e.Request.Context()).Row(&zone)
	if err != nil {
		return ""
	}
	return zone
}
func assignLegacyID(e *core.RequestEvent, r object) error {
	zone, ok := r["id"].(string)
	if !ok || zone == "" {
		return nil
	}
	var id int64
	params := dbx.Params{"zone": zone}
	ctx := e.Request.Context()
	err := e.App.DB().NewQuery("SELECT id FROM dns_interface_zones WHERE zone={:zone}").Bind(params).WithContext(ctx).Row(&id)
	if err != nil {
		_, err = e.App.DB().NewQuery("INSERT INTO dns_interface_zones(zone) VALUES({:zone}) ON CONFLICT(zone) DO NOTHING").Bind(params).WithContext(ctx).Execute()
		if err != nil {
			return err
		}
		err = e.App.DB().NewQuery("SELECT id FROM dns_interface_zones WHERE zone={:zone}").Bind(params).WithContext(ctx).Row(&id)
		if err != nil {
			return err
		}
	}
	r["id"] = id
	return nil
}
func legacyDomains(e *core.RequestEvent, out object) error {
	if rows, ok := out["rows"].([]object); ok {
		for _, r := range rows {
			if err := assignLegacyID(e, r); err != nil {
				return err
			}
		}
	}
	if detail, ok := out["data"].(object); ok {
		return assignLegacyID(e, detail)
	}
	return nil
}
