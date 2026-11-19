package dnsauth

import (
	"strconv"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"

	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/internal/rest/resp"
)

func Bind(api *router.RouterGroup[*core.RequestEvent]) {
	bindLinks(api)
	api.POST("/dns-member/password", func(e *core.RequestEvent) error {
		var input struct {
			Current  string `json:"current"`
			Password string `json:"password"`
		}
		if e.BindBody(&input) != nil || len(input.Password) < 10 || len(input.Password) > 72 || input.Current == input.Password {
			return resp.Err(e, domain.ErrInvalidParams)
		}
		err := e.App.RunInTransaction(func(tx core.App) error {
			member, err := tx.FindRecordById(Members, e.Auth.Id)
			if err != nil || member.GetBool("disabled") || !member.ValidatePassword(input.Current) {
				return domain.NewError(403, "current password incorrect")
			}
			member.SetPassword(input.Password)
			if err := tx.Save(member); err != nil {
				return domain.ErrInvalidParams
			}
			return nil
		})
		if err != nil {
			return resp.Err(e, err)
		}
		return resp.Ok(e, nil)
	}).Bind(apis.RequireAuth(Members), apis.BodyLimit(4096))
	api.GET("/dns-member/zones", func(e *core.RequestEvent) error {
		page, perPage := 1, 20
		q := e.Request.URL.Query()
		for key, value := range map[string]*int{"page": &page, "perPage": &perPage} {
			if q.Has(key) {
				n, err := strconv.Atoi(q.Get(key))
				if err != nil {
					return resp.Err(e, domain.ErrInvalidParams)
				}
				*value = n
			}
		}
		zones, total, err := ListZones(e, page, perPage)
		if err != nil {
			return resp.Err(e, err)
		}
		return resp.Ok(e, map[string]any{"items": zones, "total": total})
	}).Bind(apis.RequireAuth(Members, ZoneSessions, core.CollectionNameSuperusers))
}
