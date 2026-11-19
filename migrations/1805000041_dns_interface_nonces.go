package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		if _, err := app.DB().NewQuery(`CREATE TABLE dns_interface_nonces(
      uid TEXT NOT NULL REFERENCES dns_interface_keys(uid) ON DELETE CASCADE,
      nonce TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(uid,nonce)
     ) WITHOUT ROWID`).Execute(); err != nil {
			return err
		}
		_, err := app.DB().NewQuery("CREATE INDEX idx_dns_nonce_expiry ON dns_interface_nonces(expires)").Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().NewQuery("DROP TABLE dns_interface_nonces").Execute()
		return err
	})
}
