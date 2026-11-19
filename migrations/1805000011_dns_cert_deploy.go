package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		_, err := app.DB().NewQuery(`CREATE TABLE dns_cert_deploy (
			id TEXT PRIMARY KEY,
			access_id TEXT NOT NULL REFERENCES access(id) ON DELETE RESTRICT,
			order_id TEXT NOT NULL REFERENCES dns_cert_orders(id) ON DELETE RESTRICT,
			workflow_id TEXT NOT NULL REFERENCES workflow(id) ON DELETE RESTRICT,
			node_id TEXT NOT NULL,
			remark TEXT NOT NULL DEFAULT '',
			active INTEGER NOT NULL DEFAULT 1,
			status INTEGER NOT NULL DEFAULT 0,
			version INTEGER NOT NULL DEFAULT 1,
			process_id TEXT NOT NULL DEFAULT '',
			started INTEGER NOT NULL DEFAULT 0,
			finished INTEGER NOT NULL DEFAULT 0,
			created INTEGER NOT NULL
		);
		CREATE INDEX dns_cert_deploy_account ON dns_cert_deploy(access_id,created);
		CREATE INDEX dns_cert_deploy_order ON dns_cert_deploy(order_id);
		CREATE UNIQUE INDEX dns_cert_deploy_process ON dns_cert_deploy(process_id) WHERE process_id <> ''`).Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().NewQuery("DROP TABLE dns_cert_deploy").Execute()
		return err
	})
}
