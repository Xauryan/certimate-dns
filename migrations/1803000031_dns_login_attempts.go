package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		for _, q := range []string{
			"CREATE TABLE dns_login_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, expires INTEGER NOT NULL)",
			"CREATE INDEX idx_dns_login_attempt_source ON dns_login_attempts(source)",
			"CREATE INDEX idx_dns_login_attempt_expiry ON dns_login_attempts(expires)",
		} {
			if _, err := app.DB().NewQuery(q).Execute(); err != nil {
				return err
			}
		}
		return nil
	}, func(app core.App) error {
		_, err := app.DB().DropTable("dns_login_attempts").Execute()
		return err
	})
}
