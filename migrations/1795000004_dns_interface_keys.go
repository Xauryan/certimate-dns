package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		_, err := app.DB().NewQuery(`CREATE TABLE dns_interface_keys (
			uid TEXT PRIMARY KEY,
			owner_collection TEXT NOT NULL,
			owner TEXT NOT NULL,
			label TEXT NOT NULL,
			scope TEXT NOT NULL
		)`).Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().NewQuery("DROP TABLE dns_interface_keys").Execute()
		return err
	})
}
