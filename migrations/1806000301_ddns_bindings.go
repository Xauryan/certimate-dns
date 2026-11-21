package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		_, err := app.DB().NewQuery(`CREATE TABLE ddns_bindings (
			id TEXT PRIMARY KEY NOT NULL,
			node_id TEXT NOT NULL REFERENCES ddns_nodes(id) ON DELETE CASCADE,
			provider TEXT NOT NULL,
			access_id TEXT NOT NULL,
			zone_id TEXT NOT NULL,
			zone_name TEXT NOT NULL,
			record_id TEXT NOT NULL,
			record_name TEXT NOT NULL,
			record_type TEXT NOT NULL CHECK (record_type IN ('A', 'AAAA')),
			interface_name TEXT NOT NULL,
			last_address TEXT NOT NULL DEFAULT '',
			sync_status TEXT NOT NULL DEFAULT 'pending' CHECK (sync_status IN ('pending', 'synced', 'failed', 'waiting')),
			last_error TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL,
 attempted_address TEXT NOT NULL DEFAULT '',
 failure_count INTEGER NOT NULL DEFAULT 0,
			UNIQUE (provider, zone_id, record_id)
		);
		CREATE INDEX idx_ddns_bindings_node ON ddns_bindings(node_id)`).Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().NewQuery("DROP TABLE ddns_bindings").Execute()
		return err
	})
}
