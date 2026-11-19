package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		_, err := app.DB().NewQuery(`CREATE TABLE dns_optimize_tasks (
   id TEXT PRIMARY KEY, provider TEXT NOT NULL, access TEXT NOT NULL, zone TEXT NOT NULL,
   name TEXT NOT NULL, family TEXT NOT NULL, line TEXT NOT NULL, config TEXT NOT NULL,
   interval INTEGER NOT NULL CHECK(interval BETWEEN 10 AND 10080), enabled INTEGER NOT NULL DEFAULT 0,
   due INTEGER NOT NULL DEFAULT 0, lease INTEGER NOT NULL DEFAULT 0, last_run INTEGER NOT NULL DEFAULT 0,
   status TEXT NOT NULL DEFAULT '', UNIQUE(provider,access,zone,name,family,line)
  );
  CREATE INDEX dns_optimize_due ON dns_optimize_tasks(enabled,due);
  CREATE TABLE dns_optimize_runs(id INTEGER PRIMARY KEY, provider TEXT NOT NULL, access TEXT NOT NULL, zone TEXT NOT NULL,
    task TEXT NOT NULL, actor TEXT NOT NULL, started INTEGER NOT NULL, plan TEXT NOT NULL, status TEXT NOT NULL);
  CREATE INDEX dns_optimize_runs_zone ON dns_optimize_runs(provider,access,zone,id);`).Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().NewQuery("DROP TABLE dns_optimize_runs; DROP TABLE dns_optimize_tasks;").Execute()
		return err
	})
}
