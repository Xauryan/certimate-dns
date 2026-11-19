package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		_, err := app.DB().NewQuery(`CREATE TABLE dns_interface_zones (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     zone TEXT UNIQUE NOT NULL REFERENCES dnsZone(id) ON DELETE CASCADE,
     recordcount INTEGER NOT NULL DEFAULT 0
  )`).Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().NewQuery(`DROP TABLE dns_interface_zones`).Execute()
		return err
	})
}
