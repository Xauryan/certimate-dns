package settings

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"

	"github.com/certimate-go/certimate/internal/domain"
)

const appearanceSetting = "consoleAppearance"

type siteAppearance struct {
	Theme string `json:"theme"`
}

func (a siteAppearance) valid() bool {
	return a.Theme == "light" || a.Theme == "dark" || a.Theme == "system"
}

// BindAppearance exposes the theme on the sign-in screen and restricts writes to administrators.
func BindAppearance(api *router.RouterGroup[*core.RequestEvent]) {
	api.GET("/appearance", getAppearance)
	api.PUT("/appearance", putAppearance).Bind(apis.RequireSuperuserAuth(), apis.BodyLimit(1024))
}

func getAppearance(e *core.RequestEvent) error {
	value := siteAppearance{Theme: "dark"}
	record, err := e.App.FindFirstRecordByData(domain.CollectionNameSettings, "name", appearanceSetting)
	switch {
	case err == nil:
		var saved siteAppearance
		if record.UnmarshalJSONField("content", &saved) == nil && saved.valid() {
			value = saved
		}
	case !errors.Is(err, sql.ErrNoRows):
		return e.InternalServerError("Could not load the site appearance.", nil)
	}

	e.Response.Header().Set("Cache-Control", "no-store")
	return e.JSON(http.StatusOK, value)
}

func putAppearance(e *core.RequestEvent) error {
	var value siteAppearance
	if e.BindBody(&value) != nil || !value.valid() {
		return e.BadRequestError("Choose light, dark or system appearance.", nil)
	}

	err := e.App.RunInTransaction(func(tx core.App) error {
		collection, err := tx.FindCollectionByNameOrId(domain.CollectionNameSettings)
		if err != nil {
			return err
		}

		record, err := tx.FindFirstRecordByData(collection, "name", appearanceSetting)
		if errors.Is(err, sql.ErrNoRows) {
			record = core.NewRecord(collection)
			record.Set("name", appearanceSetting)
		} else if err != nil {
			return err
		}

		record.Set("content", value)
		return tx.Save(record)
	})
	if err != nil {
		return e.InternalServerError("Could not save the site appearance.", nil)
	}

	e.App.Logger().Info("Updated site appearance", "actor", e.Auth.Id, "theme", value.Theme)
	return e.JSON(http.StatusOK, value)
}
