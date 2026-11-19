package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		_, err := app.DB().NewQuery(`CREATE TABLE dns_cert_cnames (
			id TEXT PRIMARY KEY,
			source_zone_id TEXT NOT NULL REFERENCES dnsZone(id) ON DELETE CASCADE,
			source_name TEXT NOT NULL,
			domain TEXT NOT NULL,
			target_zone_id TEXT NOT NULL REFERENCES dnsZone(id) ON DELETE CASCADE,
			target_name TEXT NOT NULL,
			rr TEXT NOT NULL,
			status INTEGER NOT NULL DEFAULT 0 CHECK(status IN (0,1)),
			revision INTEGER NOT NULL DEFAULT 1,
			created TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
			UNIQUE(source_zone_id,domain),
			UNIQUE(target_zone_id,rr)
		)`).Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().NewQuery("DROP TABLE dns_cert_cnames").Execute()
		return err
	})
}
