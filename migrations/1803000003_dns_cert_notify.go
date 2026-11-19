package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		_, err := app.DB().NewQuery(`CREATE TABLE dns_cert_notice_settings (
			order_id TEXT PRIMARY KEY REFERENCES dns_cert_orders(id) ON DELETE CASCADE,
			access_id TEXT NOT NULL
		);
		CREATE TABLE dns_cert_notices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			order_id TEXT NOT NULL REFERENCES dns_cert_orders(id) ON DELETE CASCADE,
			access_id TEXT NOT NULL, event_key TEXT NOT NULL, action TEXT NOT NULL, state TEXT NOT NULL,
			success INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
			next_at INTEGER NOT NULL DEFAULT 0, lease TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL,
			UNIQUE(order_id,access_id,event_key)
		);
		CREATE INDEX dns_cert_notices_due ON dns_cert_notices(status,next_at,id);`).Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().NewQuery("DROP TABLE dns_cert_notices; DROP TABLE dns_cert_notice_settings").Execute()
		return err
	})
}
