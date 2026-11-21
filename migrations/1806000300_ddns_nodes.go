package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		_, err := app.DB().NewQuery(`CREATE TABLE ddns_nodes (
			id TEXT PRIMARY KEY NOT NULL,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
			report_required INTEGER NOT NULL DEFAULT 1 CHECK (report_required IN (0, 1)),
			hostname TEXT NOT NULL DEFAULT '',
			interfaces TEXT NOT NULL DEFAULT '[]',
			seen_at INTEGER NOT NULL DEFAULT 0
		)`).Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().NewQuery("DROP TABLE ddns_nodes").Execute()
		return err
	})
}
