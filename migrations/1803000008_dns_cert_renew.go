package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		_, err := app.DB().NewQuery(`CREATE TABLE dns_cert_renewals (
			root_id TEXT PRIMARY KEY,
			current_id TEXT NOT NULL,
			pending_id TEXT NOT NULL DEFAULT '',
			access_id TEXT NOT NULL,
			domain TEXT NOT NULL,
			zone_id TEXT NOT NULL,
			zone_account TEXT NOT NULL,
			zone_provider TEXT NOT NULL,
			zone_remote TEXT NOT NULL,
			zone_name TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 0,
			version INTEGER NOT NULL DEFAULT 1,
			status TEXT NOT NULL,
			next_at INTEGER NOT NULL,
			lease TEXT NOT NULL DEFAULT '',
			lease_end INTEGER NOT NULL DEFAULT 0,
			proof TEXT NOT NULL DEFAULT '',
			stage TEXT NOT NULL DEFAULT ''
		);
		CREATE UNIQUE INDEX dns_cert_renewals_target ON dns_cert_renewals(access_id,domain) WHERE enabled=1;
		CREATE INDEX dns_cert_renewals_due ON dns_cert_renewals(enabled,next_at,lease_end);
		CREATE TABLE dns_cert_renewal_orders (
			order_id TEXT PRIMARY KEY REFERENCES dns_cert_orders(id),
			root_id TEXT NOT NULL REFERENCES dns_cert_renewals(root_id) ON DELETE CASCADE
		)`).Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().NewQuery("DROP TABLE dns_cert_renewal_orders; DROP TABLE dns_cert_renewals;").Execute()
		return err
	})
}
