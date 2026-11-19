package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		_, err := app.DB().NewQuery(`CREATE TABLE dns_interface_cert_orders (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			order_id TEXT UNIQUE NOT NULL REFERENCES dns_cert_orders(id) ON DELETE CASCADE
		);
		INSERT INTO dns_interface_cert_orders(order_id) SELECT id FROM dns_cert_orders ORDER BY created,id;
		CREATE TRIGGER dns_interface_cert_order_insert AFTER INSERT ON dns_cert_orders
		BEGIN INSERT INTO dns_interface_cert_orders(order_id) VALUES(new.id); END`).Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().NewQuery("DROP TRIGGER dns_interface_cert_order_insert; DROP TABLE dns_interface_cert_orders").Execute()
		return err
	})
}
