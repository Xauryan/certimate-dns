package dnscatalog

import (
	"context"
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	"strconv"
	"unicode/utf8"
)

type BatchChange struct {
	IDs        []string `json:"ids"`
	Action     string   `json:"action"`
	Notes      string   `json:"notes"`
	Enabled    bool     `json:"enabled"`
	CategoryID string   `json:"categoryId"`
}

// ChangeDomains is atomic across all selected resources. A stale selection
// rolls back the entire change.
func ChangeDomains(ctx context.Context, app core.App, change BatchChange) error {
	if len(change.IDs) == 0 || len(change.IDs) > 500 {
		return domain.ErrInvalidParams
	}
	if change.Action == "category" {
		return AssignCategory(app, change.IDs, change.CategoryID)
	}
	switch change.Action {
	case "notes", "notice", "delete":
	default:
		return domain.ErrInvalidParams
	}
	if utf8.RuneCountInString(change.Notes) > 2048 {
		return domain.ErrInvalidParams
	}
	return app.RunInTransaction(func(tx core.App) error {
		seen := map[string]bool{}
		for _, id := range change.IDs {
			if seen[id] {
				continue
			}
			seen[id] = true
			z, err := AdminLookup(tx, id)
			if err != nil {
				return err
			}
			r, err := tx.FindRecordById("dnsZone", id)
			if err != nil {
				return err
			}
			switch change.Action {
			case "notes":
				r.Set("notes", change.Notes)
			case "notice":
				if change.Enabled && z.ExpiresOn == "" && !z.AutoRefresh {
					return domain.NewError(409, "configure an expiry date or automatic refresh before enabling reminders")
				}
				r.Set("reminderEnabled", change.Enabled)
			case "delete":
				// Tasks address provider IDs. Reimporting the same zone must never
				// resurrect automation that was configured for a removed catalog entry.
				var linked bool
				if err := tx.DB().NewQuery(`SELECT EXISTS(SELECT 1 FROM dns_automation_tasks WHERE state<>'archived' AND json_extract(config,'$.target.accountId')={:account} AND json_extract(config,'$.target.zoneId')={:zone}) OR EXISTS(SELECT 1 FROM dns_optimize_tasks WHERE access={:account} AND zone={:zone})`).Bind(dbx.Params{"account": z.AccessID, "zone": z.ZoneID}).WithContext(ctx).Row(&linked); err != nil {
					return err
				}
				if linked {
					return domain.NewError(409, "remove linked DNS tasks before removing this domain")
				}
				if err := tx.DeleteWithContext(ctx, r); err != nil {
					return err
				}
				continue
			}
			if err := tx.SaveWithContext(ctx, r); err != nil {
				return err
			}
		}
		return nil
	})
}

func bindManagement(g *router.RouterGroup[*core.RequestEvent], resolve Resolve) {
	g.GET("/accounts/{id}/discover", func(e *core.RequestEvent) error {
		page := 1
		if value := e.Request.URL.Query().Get("page"); value != "" {
			var err error
			page, err = strconv.Atoi(value)
			if err != nil {
				return reply(e, nil, domain.ErrInvalidParams)
			}
		}
		value, err := Discover(e.Request.Context(), e.App, e.Request.PathValue("id"), page, resolve)
		return reply(e, value, err)
	})
	g.POST("/accounts/{id}/import", func(e *core.RequestEvent) error {
		var input struct {
			IDs []string `json:"zoneIds"`
		}
		if e.BindBody(&input) != nil {
			return reply(e, nil, domain.ErrInvalidParams)
		}
		id := e.Request.PathValue("id")
		value, err := ImportZones(e.Request.Context(), e.App, id, input.IDs, resolve)
		audit(e, "import provider zones", id, err)
		return reply(e, value, err)
	})
	g.POST("/accounts/{id}/zones", func(e *core.RequestEvent) error {
		var input struct {
			Name string `json:"name"`
		}
		if e.BindBody(&input) != nil {
			return reply(e, nil, domain.ErrInvalidParams)
		}
		id := e.Request.PathValue("id")
		value, err := CreateZone(e.Request.Context(), e.App, id, input.Name, resolve)
		audit(e, "create provider zone", id, err)
		return reply(e, value, err)
	})
	g.POST("/domains/batch", func(e *core.RequestEvent) error {
		var input BatchChange
		if e.BindBody(&input) != nil {
			return reply(e, nil, domain.ErrInvalidParams)
		}
		err := ChangeDomains(e.Request.Context(), e.App, input)
		audit(e, "batch change domains", "", err)
		return reply(e, nil, err)
	})
	g.POST("/domains/{id}/registration", func(e *core.RequestEvent) error {
		id := e.Request.PathValue("id")
		value, err := RefreshRegistration(e.Request.Context(), e.App, id)
		audit(e, "refresh registration", id, err)
		return reply(e, value, err)
	})
}
