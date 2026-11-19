package dnscatalog

import (
	"errors"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"

	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/internal/rest/resp"
)

// Bind registers administrative routes under the existing superuser API group.
func Bind(group *router.RouterGroup[*core.RequestEvent], resolve Resolve) {
	g := group.Group("/dns-catalog").Bind(apis.RequireSuperuserAuth())
	bindManagement(g, resolve)
	bindCategories(g)
	g.GET("/accounts", func(e *core.RequestEvent) error {
		rows := []Account{}
		err := e.App.DB().NewQuery(accountQuery + " ORDER BY a.name,a.id").WithContext(e.Request.Context()).All(&rows)
		return reply(e, rows, err)
	})
	g.PATCH("/accounts/{id}", func(e *core.RequestEvent) error {
		var input struct {
			Enabled *bool   `json:"enabled"`
			Notes   *string `json:"notes"`
		}
		if e.BindBody(&input) != nil || (input.Enabled == nil && input.Notes == nil) || (input.Notes != nil && utf8.RuneCountInString(*input.Notes) > 2048) {
			return reply(e, nil, domain.ErrInvalidParams)
		}
		id := e.Request.PathValue("id")
		err := e.App.RunInTransaction(func(tx core.App) error {
			r, err := EnsureAccount(tx, id)
			if err != nil {
				return err
			}
			if input.Enabled != nil {
				r.Set("disabled", !*input.Enabled)
			}
			if input.Notes != nil {
				r.Set("notes", *input.Notes)
			}
			return tx.Save(r)
		})
		audit(e, "set account activation", id, err)
		return reply(e, nil, err)
	})
	g.POST("/accounts/{id}/sync", func(e *core.RequestEvent) error {
		id := e.Request.PathValue("id")
		n, err := syncAccount(e.Request.Context(), e.App, id, resolve)
		audit(e, "sync account", id, err)
		return reply(e, n, err)
	})
	g.GET("/notification-channels", func(e *core.RequestEvent) error {
		rows := []Link{}
		err := e.App.DB().NewQuery("SELECT id,name FROM access WHERE reserve='notif' AND deleted='' ORDER BY name,id").WithContext(e.Request.Context()).All(&rows)
		return reply(e, rows, err)
	})
	g.GET("/domains", func(e *core.RequestEvent) error {
		q := e.Request.URL.Query()
		page := 1
		if q.Has("page") {
			var err error
			page, err = strconv.Atoi(q.Get("page"))
			if err != nil {
				return reply(e, nil, domain.ErrInvalidParams)
			}
		}
		f := Filter{Page: page, AccountID: q.Get("accessId"), Search: q.Get("q"), Tag: q.Get("tag"), GroupName: q.Get("group"), Due: q.Get("due") == "true"}
		data, err := listDomains(e.Request.Context(), e.App, f, time.Now())
		return reply(e, data, err)
	})
	g.GET("/domains/{id}", func(e *core.RequestEvent) error {
		d, err := detail(e.Request.Context(), e.App, e.Request.PathValue("id"))
		return reply(e, d, err)
	})
	// PUT replaces only the local administrative metadata.
	g.PUT("/domains/{id}/metadata", func(e *core.RequestEvent) error {
		var input Metadata
		if e.BindBody(&input) != nil {
			return reply(e, nil, domain.ErrInvalidParams)
		}
		id := e.Request.PathValue("id")
		err := UpdateMetadata(e.App, id, input)
		audit(e, "edit domain metadata", id, err)
		return reply(e, nil, err)
	})
}

func audit(e *core.RequestEvent, action, id string, err error) {
	e.App.Logger().Info("DNS catalog change", "action", action, "actor", e.Auth.Id, "actorCollection", e.Auth.Collection().Name, "resource", id, "success", err == nil)
}

func reply(e *core.RequestEvent, value any, err error) error {
	if err == nil {
		return resp.Ok(e, value)
	}
	var known *domain.Error
	if errors.As(err, &known) {
		return resp.Err(e, known)
	}
	return resp.Err(e, domain.NewError(500, "DNS catalog operation failed"))
}
