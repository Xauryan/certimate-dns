// This fixture runs the PocketBase REST API with Certimate v0.4.38's migrations.
// The integration runner verifies the historical sources before building it.
package main

import (
	"log"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"

	_ "github.com/certimate-go/certimate/migrations"
)

func main() {
	var legacy core.MigrationsList
	for _, m := range core.AppMigrations.Items() {
		if m.File <= "1788364800_upgrade_v0.4.33.go" {
			legacy.Add(m)
		}
	}
	if len(legacy.Items()) != 16 {
		log.Fatal("unexpected v0.4.38 migration set")
	}
	core.AppMigrations = legacy
	if err := pocketbase.New().Start(); err != nil {
		log.Fatal(err)
	}
}
