package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		_, err := app.DB().NewQuery(`CREATE TABLE dns_import_promotions(
			source TEXT NOT NULL,kind TEXT NOT NULL,legacy_id INTEGER NOT NULL,target_id TEXT NOT NULL,
			source_digest TEXT NOT NULL,binding TEXT NOT NULL CHECK(json_valid(binding)),confirmed_at INTEGER NOT NULL,
			PRIMARY KEY(source,kind,legacy_id),FOREIGN KEY(source,kind,legacy_id) REFERENCES dns_import_items(source,kind,legacy_id) ON DELETE CASCADE
		) WITHOUT ROWID;
		CREATE INDEX dns_import_promotions_target ON dns_import_promotions(source,kind,target_id)`).Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().NewQuery("DROP TABLE dns_import_promotions").Execute()
		return err
	})
}
