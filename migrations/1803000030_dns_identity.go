package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		// Private service state. These tables have no PocketBase collection routes.
		for _, query := range []string{
			`CREATE TABLE dns_qq_notification (id INTEGER PRIMARY KEY CHECK(id=1),
				enabled BOOLEAN NOT NULL DEFAULT FALSE, app_id TEXT NOT NULL DEFAULT '',
				open_id TEXT NOT NULL DEFAULT '', confirmed_at INTEGER NOT NULL DEFAULT 0, bind_hash TEXT NOT NULL DEFAULT '', bind_expires INTEGER NOT NULL DEFAULT 0)`,
			`INSERT INTO dns_qq_notification (id) VALUES (1)`,
			`CREATE TABLE dns_login_policy (id INTEGER PRIMARY KEY CHECK(id=1), captcha BOOLEAN NOT NULL DEFAULT FALSE)`,
			`INSERT INTO dns_login_policy (id) VALUES (1)`,
			`CREATE TABLE dns_member_totp (
				member TEXT PRIMARY KEY REFERENCES dns_members(id) ON DELETE CASCADE,
				seed TEXT NOT NULL, active BOOLEAN NOT NULL DEFAULT FALSE, expires INTEGER NOT NULL,
				last_step INTEGER NOT NULL DEFAULT 0, challenge TEXT, challenge_expires INTEGER,
				session_fingerprint TEXT, auth_method TEXT, mfa_ref TEXT, tries INTEGER NOT NULL DEFAULT 0, tries_expire INTEGER NOT NULL DEFAULT 0)`,
			`CREATE UNIQUE INDEX idx_dns_totp_challenge ON dns_member_totp(challenge)`,
		} {
			if _, err := app.DB().NewQuery(query).Execute(); err != nil {
				return err
			}
		}
		return nil
	}, func(app core.App) error {
		for _, name := range []string{"dns_member_totp", "dns_login_policy", "dns_qq_notification"} {
			if _, err := app.DB().DropTable(name).Execute(); err != nil {
				return err
			}
		}
		return nil
	})
}
