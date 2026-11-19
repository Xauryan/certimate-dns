package dnscatalog

import (
	"database/sql"
	"errors"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/list"
	"github.com/pocketbase/pocketbase/tools/router"

	"github.com/certimate-go/certimate/internal/domain"
)

// DomainCount includes all assigned local zones, including last-known provider zones.
type Category struct {
	ID          string `db:"id" json:"id"`
	Name        string `db:"name" json:"name"`
	Remark      string `db:"remark" json:"remark"`
	Sort        int    `db:"sort" json:"sort"`
	DomainCount int    `db:"domain_count" json:"domain_count"`
}

type CategoryPatch struct {
	Name   *string `json:"name"`
	Remark *string `json:"remark"`
	Sort   *int    `json:"sort"`
}

const selectCategory = `SELECT c.id,c.name,c.remark,cast(c.sort AS integer) AS sort,
	(SELECT count(*) FROM dnsZone z WHERE z.categoryRef=c.id) AS domain_count
	FROM dnsCategory c`

// ListCategories includes global counts and is intended for catalog administrators.
func ListCategories(app core.App) ([]Category, error) {
	rows := []Category{}
	err := app.DB().NewQuery(selectCategory + " ORDER BY c.sort ASC,c.id DESC").All(&rows)
	return rows, err
}

func lookupCategory(app core.App, id string) (*Category, error) {
	var c Category
	err := app.DB().NewQuery(selectCategory + " WHERE c.id={:id}").Bind(dbx.Params{"id": id}).One(&c)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrRecordNotFound
	}
	return &c, err
}

// SaveCategory applies partial edits and keeps existing group-name readers in sync.
func SaveCategory(app core.App, id string, p CategoryPatch) (*Category, error) {
	if p.Name == nil && p.Remark == nil && p.Sort == nil || id == "" && p.Name == nil {
		return nil, domain.ErrInvalidParams
	}
	var result *Category
	err := app.RunInTransaction(func(tx core.App) error {
		var r *core.Record
		if id == "" {
			c, err := tx.FindCollectionByNameOrId("dnsCategory")
			if err != nil {
				return err
			}
			r = core.NewRecord(c)
		} else {
			var err error
			r, err = tx.FindRecordById("dnsCategory", id)
			if errors.Is(err, sql.ErrNoRows) {
				return domain.ErrRecordNotFound
			}
			if err != nil {
				return err
			}
		}
		if p.Name != nil {
			name := strings.TrimSpace(*p.Name)
			if len(name) == 0 || utf8.RuneCountInString(name) > 128 {
				return domain.ErrInvalidParams
			}
			var exists bool
			if err := tx.DB().NewQuery("SELECT EXISTS(SELECT 1 FROM dnsCategory WHERE name={:name} AND id<>{:id})").Bind(dbx.Params{"name": name, "id": id}).Row(&exists); err != nil {
				return err
			}
			if exists {
				return domain.NewError(409, "category name already in use")
			}
			r.Set("name", name)
		}
		if p.Remark != nil {
			remark := strings.TrimSpace(*p.Remark)
			if utf8.RuneCountInString(remark) > 100 {
				return domain.ErrInvalidParams
			}
			r.Set("remark", remark)
		}
		if p.Sort != nil {
			if *p.Sort < math.MinInt32 || *p.Sort > math.MaxInt32 {
				return domain.ErrInvalidParams
			}
			r.Set("sort", *p.Sort)
		}
		if err := tx.Save(r); err != nil {
			return err
		}
		if p.Name != nil {
			// An existing free-form group of the same name becomes part of the category.
			_, err := tx.DB().NewQuery(`UPDATE dnsZone SET groupName={:name},categoryRef={:id}
				WHERE categoryRef={:id} OR (categoryRef='' AND groupName={:name})`).Bind(dbx.Params{"name": r.GetString("name"), "id": r.Id}).Execute()
			if err != nil {
				return err
			}
		}
		var err error
		result, err = lookupCategory(tx, r.Id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func DeleteCategory(app core.App, id string) error {
	return app.RunInTransaction(func(tx core.App) error {
		c, err := lookupCategory(tx, id)
		if err != nil {
			return err
		}
		if c.DomainCount != 0 {
			return domain.NewError(409, "category has assigned zones")
		}
		r, err := tx.FindRecordById("dnsCategory", id)
		if err != nil {
			return err
		}
		return tx.Delete(r)
	})
}

// AssignCategory atomically moves the selected zones. Empty categoryID clears the assignment.
func AssignCategory(app core.App, ids []string, categoryID string) error {
	if len(ids) == 0 || len(ids) > 500 {
		return domain.ErrInvalidParams
	}
	return app.RunInTransaction(func(tx core.App) error {
		name := ""
		if categoryID != "" {
			c, err := lookupCategory(tx, categoryID)
			if err != nil {
				return err
			}
			name = c.Name
		}
		seen := map[string]bool{}
		for _, id := range ids {
			if id == "" || seen[id] {
				return domain.ErrInvalidParams
			}
			seen[id] = true
		}
		result, err := tx.DB().Update("dnsZone", dbx.Params{"categoryRef": categoryID, "groupName": name}, dbx.In("id", list.ToInterfaceSlice(ids)...)).Execute()
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != int64(len(ids)) {
			return domain.ErrRecordNotFound
		}
		return nil
	})
}

// setZoneGroupName resolves the historic free-text metadata input to a category when one exists.
func setZoneGroupName(tx core.App, r *core.Record, name string) error {
	var id string
	err := tx.DB().NewQuery("SELECT coalesce((SELECT id FROM dnsCategory WHERE name={:name}),'')").Bind(dbx.Params{"name": name}).Row(&id)
	if err != nil {
		return err
	}
	r.Set("groupName", name)
	r.Set("categoryRef", id)
	return nil
}

func bindCategories(g *router.RouterGroup[*core.RequestEvent]) {
	g.GET("/categories", func(e *core.RequestEvent) error {
		rows, err := ListCategories(e.App)
		return reply(e, rows, err)
	})
	write := func(e *core.RequestEvent) error {
		var patch CategoryPatch
		if e.BindBody(&patch) != nil {
			return reply(e, nil, domain.ErrInvalidParams)
		}
		id := e.Request.PathValue("id")
		c, err := SaveCategory(e.App, id, patch)
		if c != nil {
			id = c.ID
		}
		audit(e, "save domain category", id, err)
		return reply(e, c, err)
	}
	g.POST("/categories", write)
	g.PATCH("/categories/{id}", write)
	g.DELETE("/categories/{id}", func(e *core.RequestEvent) error {
		id := e.Request.PathValue("id")
		err := DeleteCategory(e.App, id)
		audit(e, "delete domain category", id, err)
		return reply(e, nil, err)
	})
}
