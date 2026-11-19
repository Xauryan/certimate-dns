package dnscert

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"

	"github.com/certimate-go/certimate/internal/dnscatalog"
	"github.com/certimate-go/certimate/internal/domain"
)

// Commercial CA credentials are independent of the account's DNS-record permission.
const issuerAccounts = ` FROM access a WHERE a.deleted='' AND a.reserve IN ('','ca') AND a.provider IN ('aliyun','tencentcloud','ucloud')`

type Page[T any] struct {
	Items []T `json:"items"`
	Total int `json:"total"`
}

type Event struct {
	ID      int64  `db:"id" json:"id"`
	Action  string `db:"action" json:"action"`
	State   string `db:"state" json:"state"`
	Success bool   `db:"success" json:"success"`
	Created int64  `db:"created" json:"created"`
}

func writeEvent(app core.App, id, action, state string, ok bool) error {
	_, err := app.DB().Insert("dns_cert_events", dbx.Params{"order_id": id, "action": action, "state": state, "success": ok, "created": time.Now().Unix()}).Execute()
	if err != nil {
		return err
	}
	return notifyOrderEvent(app, id, action, state, ok)
}

// The predicates are supplied by each authorized route before count and pagination.
func pageRows[T any](ctx context.Context, app core.App, fields, from, sort string, params dbx.Params, page int) (Page[T], error) {
	out := Page[T]{Items: []T{}}
	if page < 1 || page > 1000000 {
		return out, errInput
	}
	params["offset"] = (page - 1) * 20
	err := app.DB().NewQuery("SELECT count(*) " + from).Bind(params).WithContext(ctx).Row(&out.Total)
	if err == nil {
		err = app.DB().NewQuery("SELECT " + fields + " " + from + " ORDER BY " + sort + " LIMIT 20 OFFSET {:offset}").Bind(params).WithContext(ctx).All(&out.Items)
	}
	return out, err
}

func OrderEvents(ctx context.Context, app core.App, id string, page int) (Page[Event], error) {
	return pageRows[Event](ctx, app, "id,action,state,success,created", "FROM dns_cert_events WHERE order_id={:id}", "id DESC", dbx.Params{"id": id}, page)
}

func validateSourceZone(app core.App, zoneID, name string) error {
	if zoneID == "" {
		return nil
	}
	z, err := dnscatalog.Lookup(app, zoneID)
	if err != nil {
		return err
	}
	root, err := canonicalDomain(z.Name)
	if err != nil || (name != root && !strings.HasSuffix(name, "."+root)) {
		return errInput
	}
	return nil
}

func validateRequest(app core.App, req *OrderRequest, provider string) error {
	if err := req.validate(provider); err != nil {
		return err
	}
	return validateSourceZone(app, req.SourceZoneID, req.Domain)
}

func pageNumber(e *core.RequestEvent) int {
	s := e.Request.URL.Query().Get("page")
	if s == "" {
		return 1
	}
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return p
}

// PublicError maps provider, storage and scope failures to stable messages without remote response data.
func PublicError(err error) (int, string) {
	switch {
	case err == nil:
		return http.StatusOK, ""
	case errors.Is(err, errMissing), errors.Is(err, domain.ErrRecordNotFound):
		return http.StatusNotFound, "Certificate order or account not available"
	case errors.Is(err, errInput), errors.Is(err, domain.ErrInvalidParams):
		return http.StatusBadRequest, "Invalid certificate order input"
	case errors.Is(err, errConflict):
		return http.StatusConflict, "Order changed or requires reconciliation"
	case errors.Is(err, errProvider):
		return http.StatusBadGateway, "Certificate provider request failed"
	default:
		return http.StatusInternalServerError, "Certificate order operation failed"
	}
}

func reply(e *core.RequestEvent, v any, err error) error {
	if err == nil {
		return e.JSON(http.StatusOK, v)
	}
	status, message := PublicError(err)
	return e.Error(status, message, nil)
}

func Bind(group *router.RouterGroup[*core.RequestEvent], accesses accessReader, resolve dnscatalog.Resolve) *Service {
	s := NewService(accesses, resolve)
	s.bind(group)
	return s
}

func (s *Service) bind(group *router.RouterGroup[*core.RequestEvent]) {
	g := group.Group("/dnscert").Bind(apis.RequireSuperuserAuth(), apis.BodyLimit(16<<10))
	bindRenew(g, s)
	bindNotification(g)
	g.GET("/accounts", func(e *core.RequestEvent) error {
		type account struct {
			ID       string `json:"id" db:"id"`
			Name     string `json:"name" db:"name"`
			Provider string `json:"provider" db:"provider"`
		}
		rows := []account{}
		err := e.App.DB().NewQuery("SELECT a.id,a.name,a.provider" + issuerAccounts + " ORDER BY a.name,a.id").WithContext(e.Request.Context()).All(&rows)
		return reply(e, map[string]any{"items": rows}, err)
	})
	g.POST("/accounts/{id}/check", func(e *core.RequestEvent) error {
		ctx, cancel := context.WithTimeout(e.Request.Context(), 30*time.Second)
		defer cancel()
		a, err := s.account(ctx, e.App, e.Request.PathValue("id"))
		if err != nil {
			return reply(e, nil, err)
		}
		issuer, err := s.issuer(a)
		if err == nil {
			err = issuer.Check(ctx)
		}
		return reply(e, map[string]bool{"ok": err == nil}, err)
	})
	g.GET("/orders", func(e *core.RequestEvent) error {
		// Contact details and all certificate material stay outside list projections.
		const cols = "id,primary_zone_id,replacement_id,access_id,provider,domain,algorithm,state,remote_id,certificate_id,version,challenges_json,lease_end,created,updated"
		page, err := pageRows[Order](e.Request.Context(), e.App, cols, "FROM dns_cert_orders WHERE state!='deleted'", "created DESC,id", dbx.Params{}, pageNumber(e))
		for i := range page.Items {
			if err != nil {
				break
			}
			err = page.Items[i].project()
		}
		return reply(e, page, err)
	})
	g.GET("/orders/{id}", func(e *core.RequestEvent) error {
		o, err := ReadOrder(e.App, e.Request.PathValue("id"))
		var req *OrderRequest
		if err == nil && o.State == "draft" {
			err = json.Unmarshal([]byte(o.RequestJSON), &req)
		}
		return reply(e, struct {
			Order
			Request *OrderRequest `json:"request,omitempty"`
		}{o, req}, err)
	})
	g.GET("/orders/{id}/events", func(e *core.RequestEvent) error {
		id := e.Request.PathValue("id")
		if _, err := ReadOrder(e.App, id); err != nil {
			return reply(e, nil, err)
		}
		page, err := OrderEvents(e.Request.Context(), e.App, id, pageNumber(e))
		return reply(e, page, err)
	})
	g.GET("/zones", func(e *core.RequestEvent) error {
		q := e.Request.URL.Query()
		var o Order
		var err error
		if q.Has("orderId") {
			o, err = ReadOrder(e.App, q.Get("orderId"))
		} else {
			o.Domain, err = canonicalDomain(q.Get("domain"))
		}
		if err != nil {
			return reply(e, nil, err)
		}
		type zone struct {
			ID        string `json:"id" db:"id"`
			Name      string `json:"name" db:"name"`
			AccountID string `json:"accountId" db:"accountId"`
		}
		const from = `FROM dnsZone z JOIN dnsAccount d ON d.id=z.accountRef AND d.disabled=0
            JOIN access a ON a.id=d.accessRef AND a.id=d.id AND a.deleted=''
            WHERE z.present=1 AND ({:bound}='' OR z.id={:bound})
            AND (lower(rtrim(z.name,'.'))={:name} OR substr({:name},-length(rtrim(z.name,'.'))-1)='.'||lower(rtrim(z.name,'.')))`
		page, err := pageRows[zone](e.Request.Context(), e.App, "z.id,z.name,a.id AS accountId", from, "z.name,z.id", dbx.Params{"name": o.Domain, "bound": o.PrimaryZoneID}, pageNumber(e))
		return reply(e, page, err)
	})
	g.POST("/orders", func(e *core.RequestEvent) error {
		var in struct {
			AccessID string       `json:"accessId"`
			Request  OrderRequest `json:"request"`
		}
		if e.BindBody(&in) != nil {
			return reply(e, nil, errInput)
		}
		data, err := s.Draft(e.Request.Context(), e.App, in.AccessID, in.Request)
		return reply(e, data, err)
	})
	g.POST("/orders/{id}/{action}", func(e *core.RequestEvent) error {
		var in ActionInput
		if e.BindBody(&in) != nil {
			return reply(e, nil, errInput)
		}
		in.superuserRecovery = e.HasSuperuserAuth()
		data, err := s.Act(e.Request.Context(), e.App, e.Request.PathValue("id"), e.Request.PathValue("action"), in)
		return reply(e, data, err)
	})
}
