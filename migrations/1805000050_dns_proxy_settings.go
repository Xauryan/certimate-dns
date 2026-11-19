package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		_, err := app.DB().NewQuery(`CREATE TABLE dns_proxy_settings (
            id INTEGER PRIMARY KEY CHECK(id=1), enabled BOOLEAN NOT NULL DEFAULT FALSE,
            server TEXT NOT NULL DEFAULT '', credentials TEXT NOT NULL DEFAULT ''
        ); INSERT INTO dns_proxy_settings(id) VALUES (1)`).Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().DropTable("dns_proxy_settings").Execute()
		return err
	})
}
