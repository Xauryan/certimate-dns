package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		_, err := app.DB().NewQuery(`CREATE TABLE dns_import_items (
   source TEXT NOT NULL, kind TEXT NOT NULL, legacy_id INTEGER NOT NULL,
   target_id TEXT NOT NULL, digest TEXT NOT NULL, disposition TEXT NOT NULL,
   details TEXT NOT NULL, PRIMARY KEY (source,kind,legacy_id)
  ) WITHOUT ROWID`).Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().NewQuery(`DROP TABLE dns_import_items`).Execute()
		return err
	})
}
