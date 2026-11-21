package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		_, err := app.DB().NewQuery(`CREATE TABLE ddns_binding_renames (
			binding_id TEXT PRIMARY KEY NOT NULL REFERENCES ddns_bindings(id) ON DELETE CASCADE,
			target_name TEXT NOT NULL,
			interface_name TEXT NOT NULL,
			source_snapshot TEXT NOT NULL,
			evidence TEXT NOT NULL DEFAULT '',
			submitted INTEGER NOT NULL DEFAULT 0 CHECK (submitted IN (0, 1)),
			submitted_at INTEGER NOT NULL DEFAULT 0,
            reported_id TEXT NOT NULL DEFAULT '',
            candidate_id TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		)`).Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().NewQuery("DROP TABLE ddns_binding_renames").Execute()
		return err
	})
}
