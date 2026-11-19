package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		accounts, err := app.FindCollectionByNameOrId("acme_accounts")
		if err != nil {
			return err
		}
		accounts.Fields.Add(&core.TextField{Name: "googleProjectId", Max: 30, Hidden: true})
		accounts.AddIndex("idx_acme_google_project_account", true, "ca, acmeDirUrl, email, googleProjectId", "googleProjectId != ''")
		return app.Save(accounts)
	}, func(app core.App) error {
		accounts, err := app.FindCollectionByNameOrId("acme_accounts")
		if err != nil {
			return err
		}
		accounts.RemoveIndex("idx_acme_google_project_account")
		accounts.Fields.RemoveByName("googleProjectId")
		return app.Save(accounts)
	})
}
