package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		for _, q := range []string{
			"CREATE TABLE dns_monitor_log_cutoffs (task TEXT PRIMARY KEY, cutoff INTEGER NOT NULL)",
			`CREATE TABLE dns_optimize_groups (id TEXT PRIMARY KEY, zone TEXT NOT NULL, config TEXT NOT NULL CHECK(json_valid(config)), children TEXT NOT NULL CHECK(json_valid(children)))`,
			"CREATE INDEX idx_dns_optimize_groups_zone ON dns_optimize_groups(zone)",
		} {
			if _, err := app.DB().NewQuery(q).Execute(); err != nil {
				return err
			}
		}
		return nil
	}, func(app core.App) error {
		for _, q := range []string{"DROP TABLE dns_optimize_groups", "DROP TABLE dns_monitor_log_cutoffs"} {
			if _, err := app.DB().NewQuery(q).Execute(); err != nil {
				return err
			}
		}
		return nil
	})
}
