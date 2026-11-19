package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		// The Linux and Windows accounts share the same config field names.
		// Change only records which the DNSMgr interface explicitly classified.
		_, err := app.DB().NewQuery(`UPDATE access SET provider='baotapanelgo' WHERE provider='baotapanel' AND
		id IN (SELECT access_id FROM dns_cert_account_meta WHERE deploy=1 AND legacy_type='btwin')`).Execute()
		return err
	}, func(core.App) error { return nil })
}
