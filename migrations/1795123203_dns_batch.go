package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		_, err := app.DB().NewQuery(`CREATE TABLE dns_batch_plans (
   id TEXT PRIMARY KEY, provider TEXT NOT NULL, access TEXT NOT NULL, zone TEXT NOT NULL,
   actor TEXT NOT NULL, created INTEGER NOT NULL, revision INTEGER NOT NULL DEFAULT 0,
   state TEXT NOT NULL, digest TEXT NOT NULL, items TEXT NOT NULL
  );
  CREATE INDEX dns_batch_zone_history ON dns_batch_plans(provider,access,zone,created DESC,id)`).Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().NewQuery("DROP TABLE dns_batch_plans").Execute()
		return err
	})
}
