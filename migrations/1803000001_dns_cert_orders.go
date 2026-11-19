package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		_, err := app.DB().NewQuery(`CREATE TABLE dns_cert_orders (
            id TEXT PRIMARY KEY,
            access_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            domain TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            request_json TEXT NOT NULL,
            state TEXT NOT NULL,
            remote_id TEXT NOT NULL DEFAULT '',
            certificate_id TEXT NOT NULL DEFAULT '',
            primary_zone_id TEXT NOT NULL DEFAULT '',
            replacement_id TEXT NOT NULL DEFAULT '',
            challenges_json TEXT NOT NULL DEFAULT '[]',
            lease_end INTEGER NOT NULL DEFAULT 0,
            version INTEGER NOT NULL DEFAULT 1,
            created INTEGER NOT NULL,
            updated INTEGER NOT NULL
        );
        CREATE INDEX dns_cert_orders_recent ON dns_cert_orders(created DESC,id);
        CREATE UNIQUE INDEX dns_cert_orders_remote ON dns_cert_orders(access_id,remote_id)
        WHERE remote_id <> '' AND state NOT IN ('cancelled','revoked','expired','failed');
        CREATE TABLE dns_cert_challenges (
            id TEXT PRIMARY KEY,
            local_zone TEXT NOT NULL,
            provider TEXT NOT NULL,
            access_id TEXT NOT NULL,
            remote_zone TEXT NOT NULL,
            zone_name TEXT NOT NULL,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'prepared',
            record_id TEXT NOT NULL DEFAULT '',
            snapshot TEXT NOT NULL DEFAULT '',
            UNIQUE(provider, access_id, remote_zone, name, type, value)
        );
        CREATE TABLE dns_cert_challenge_refs (
            order_id TEXT NOT NULL REFERENCES dns_cert_orders(id),
            challenge_id TEXT NOT NULL REFERENCES dns_cert_challenges(id) ON DELETE CASCADE,
            PRIMARY KEY(order_id,challenge_id)
        );
        CREATE INDEX dns_cert_challenge_holders ON dns_cert_challenge_refs(challenge_id);
        CREATE TABLE dns_cert_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id TEXT NOT NULL,
            action TEXT NOT NULL,
            state TEXT NOT NULL,
            success INTEGER NOT NULL,
            created INTEGER NOT NULL
        );
        CREATE INDEX dns_cert_order_events ON dns_cert_events(order_id,id DESC);`).Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().NewQuery("DROP TABLE dns_cert_events; DROP TABLE dns_cert_challenge_refs; DROP TABLE dns_cert_challenges; DROP TABLE dns_cert_orders").Execute()
		return err
	})
}
