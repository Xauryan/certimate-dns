package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		_, err := app.DB().NewQuery(`CREATE TABLE dns_cert_account_meta (
			access_id TEXT PRIMARY KEY REFERENCES access(id) ON DELETE CASCADE,
			legacy_type TEXT NOT NULL, deploy INTEGER NOT NULL CHECK (deploy IN (0,1)),
			remark TEXT NOT NULL DEFAULT ''
		)`).Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().NewQuery("DROP TABLE dns_cert_account_meta").Execute()
		return err
	})
}
