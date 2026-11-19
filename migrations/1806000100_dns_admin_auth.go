package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		for _, query := range []string{
			`ALTER TABLE dns_login_attempts ADD COLUMN scope TEXT NOT NULL DEFAULT ''`,
			`CREATE TABLE dns_admin_auth_policy (id INTEGER PRIMARY KEY CHECK(id=1), captcha BOOLEAN NOT NULL DEFAULT FALSE)`,
			`INSERT INTO dns_admin_auth_policy (id) VALUES (1)`,
			`CREATE TABLE dns_admin_totp (
				admin TEXT PRIMARY KEY REFERENCES _superusers(id) ON DELETE CASCADE,
				seed TEXT NOT NULL, fingerprint TEXT NOT NULL DEFAULT '', last_step INTEGER NOT NULL,
				challenge TEXT, challenge_expires INTEGER NOT NULL DEFAULT 0, challenge_source TEXT,
				tries INTEGER NOT NULL DEFAULT 0, tries_expires INTEGER NOT NULL DEFAULT 0)`,
			`CREATE UNIQUE INDEX idx_dns_admin_totp_challenge ON dns_admin_totp(challenge)`,
			`CREATE TABLE dns_admin_totp_enrollment (
				admin TEXT PRIMARY KEY REFERENCES _superusers(id) ON DELETE CASCADE,
				seed TEXT NOT NULL, fingerprint TEXT NOT NULL, expires INTEGER NOT NULL,
				tries INTEGER NOT NULL DEFAULT 0)`,
		} {
			if _, err := app.DB().NewQuery(query).Execute(); err != nil {
				return err
			}
		}
		return nil
	}, func(app core.App) error {
		for _, name := range []string{"dns_admin_totp_enrollment", "dns_admin_totp", "dns_admin_auth_policy"} {
			if _, err := app.DB().DropTable(name).Execute(); err != nil {
				return err
			}
		}
		if _, err := app.DB().NewQuery("DELETE FROM dns_login_attempts WHERE scope = 'admin'").Execute(); err != nil {
			return err
		}
		_, err := app.DB().NewQuery("ALTER TABLE dns_login_attempts DROP COLUMN scope").Execute()
		return err
	})
}
