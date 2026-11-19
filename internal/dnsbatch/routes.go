package dnsbatch

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/internal/rest/resp"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
)

type Resolver func(context.Context, string, string, bool) (dns.Provider, error)
type request struct {
	e      *core.RequestEvent
	s      scope
	origin string
	client dns.Provider
}
type resultFunc func(request) (any, error)

func (r request) authorize(write bool) error {
	z, err := dnsauth.FindZone(r.e, r.s.provider, r.s.access, r.s.zone, write)
	if err != nil {
		return err
	}
	if canonicalName(z.Name) != canonicalName(r.origin) {
		return domain.ErrRecordNotFound
	}
	return nil
}

func Bind(api *router.RouterGroup[*core.RequestEvent], resolve Resolver) {
	g := api.Group("/dns/{provider}/{access}/zones/{zone}/batch")
	// Only apply and reconcile share a lock. The SQL claim protects against
	// replay; the lock prevents reconciliation of a locally executing plan.
	var active sync.Map
	wrap := func(write bool, fn resultFunc) func(*core.RequestEvent) error {
		return func(e *core.RequestEvent) error {
			s := scope{provider: e.Request.PathValue("provider"), access: e.Request.PathValue("access"), zone: e.Request.PathValue("zone")}
			z, err := dnsauth.FindZone(e, s.provider, s.access, s.zone, write)
			if err != nil {
				return resp.Err(e, err)
			}
			s.actor = e.Auth.Collection().Name + "/" + e.Auth.Id
			p, err := resolve(e.Request.Context(), s.provider, s.access, false)
			if err != nil {
				return resp.Err(e, domain.NewError(400, "could not open DNS provider"))
			}
			r := request{e: e, s: s, origin: z.Name, client: p}
			out, err := fn(r)
			if err != nil {
				var public *domain.Error
				switch {
				case errors.As(err, &public):
					return resp.Err(e, public)
				case errors.Is(err, errConflict):
					return resp.Err(e, domain.NewError(409, err.Error()))
				case errors.Is(err, errMissing):
					return resp.Err(e, domain.ErrRecordNotFound)
				default:
					return resp.Err(e, domain.NewError(500, "could not complete DNS batch request"))
				}
			}
			if err := r.authorize(write); err != nil {
				return resp.Err(e, err)
			}
			e.Response.Header().Set("Cache-Control", "no-store")
			return resp.Ok(e, out)
		}
	}
	lock := func(fn resultFunc) resultFunc {
		return func(r request) (any, error) {
			key := [4]string{r.s.provider, r.s.access, r.s.zone, r.e.Request.PathValue("id")}
			if _, busy := active.LoadOrStore(key, true); busy {
				return nil, errConflict
			}
			defer active.Delete(key)
			return fn(r)
		}
	}
	g.GET("/features", wrap(false, func(r request) (any, error) {
		_, groups := r.client.(Groups)
		_, logs := r.client.(ProviderHistory)
		caps, _ := dns.ProviderCapabilities(r.s.provider)
		edit, _ := dns.RecordEditCapabilitiesForZone(r.e.Request.Context(), r.client, r.s.zone)
		return map[string]any{"fields": fields(r.client), "capabilities": caps, "createLine": caps.Line, "groups": groups, "logs": logs, "edit": edit}, nil
	}))
	g.GET("/groups", wrap(false, func(r request) (any, error) {
		g, ok := r.client.(Groups)
		if !ok {
			return nil, domain.NewError(400, "record groups unavailable")
		}
		return g.BatchGroups(r.e.Request.Context(), r.s.zone)
	}))
	g.GET("/logs", wrap(false, func(r request) (any, error) {
		p, ok := r.client.(ProviderHistory)
		if !ok {
			return nil, domain.NewError(400, "provider record history unavailable")
		}
		n, err := page(r)
		if err != nil {
			return nil, err
		}
		return p.BatchLogs(r.e.Request.Context(), r.s.zone, n)
	}))
	g.GET("/history", wrap(false, func(r request) (any, error) {
		n, err := page(r)
		if err != nil {
			return nil, err
		}
		return history(r.e.App.DB(), r.s, n)
	}))
	g.GET("/export", wrap(false, func(r request) (any, error) {
		format := r.e.Request.URL.Query().Get("format")
		if format != "bind" && format != "json" && format != "archive" {
			return nil, domain.ErrInvalidParams
		}
		if p, ok := r.client.(interface {
			ExportDNSZone(context.Context, string) (string, error)
		}); format == "bind" && ok {
			return p.ExportDNSZone(r.e.Request.Context(), r.s.zone)
		}
		rows, err := zoneRecords(r.e.Request.Context(), r.client, r.s.zone, r.origin)
		if err != nil {
			return nil, err
		}
		if format == "archive" {
			return archive(r, rows)
		}
		if format == "json" {
			return rows, nil
		}
		_, assignments, err := groupMembership(r.e.Request.Context(), r.client, r.s.zone, rows)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if assignments[row.ID] != "" {
				return nil, domain.NewError(400, "BIND cannot represent record groups; use the versioned JSON export")
			}
		}
		value, err := exportZone(rows, r.origin, r.s.provider)
		if err != nil {
			return nil, domain.NewError(400, err.Error())
		}
		return value, nil
	}))
	g.GET("/search", wrap(false, search))
	g.POST("/preview", wrap(true, preview))
	g.GET("/plans/{id}", wrap(false, func(r request) (any, error) {
		p, err := loadPlan(r.e.App.DB(), r.s, r.e.Request.PathValue("id"))
		if err != nil {
			return nil, err
		}
		return p.public(), nil
	}))
	g.POST("/plans/{id}/apply", wrap(true, lock(func(r request) (any, error) {
		var input struct {
			Confirm bool     `json:"confirm"`
			Changes []Change `json:"changes"`
		}
		if err := body(r, &input); err != nil || !input.Confirm {
			return nil, domain.ErrInvalidParams
		}
		db := r.e.App.DB()
		p, err := loadPlan(db, r.s, r.e.Request.PathValue("id"))
		if err != nil {
			return nil, err
		}
		err = p.apply(r.e.Request.Context(), db, r.client, r.s, r.origin, input.Changes, func() error {
			return r.authorize(true)
		})
		if err != nil {
			return nil, err
		}
		return p.public(), nil
	})))
	g.POST("/plans/{id}/reconcile", wrap(true, lock(func(r request) (any, error) {
		db := r.e.App.DB()
		p, err := loadPlan(db, r.s, r.e.Request.PathValue("id"))
		if err != nil {
			return nil, err
		}
		err = p.reconcile(r.e.Request.Context(), db, r.client, r.s, r.origin, func() error {
			return r.authorize(true)
		})
		if err != nil {
			return nil, err
		}
		return p.public(), nil
	})))
}
func page(r request) (int, error) {
	s := r.e.Request.URL.Query().Get("page")
	if s == "" {
		return 1, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 1000000 {
		return 0, domain.ErrInvalidParams
	}
	return n, nil
}
func body(r request, out any) error {
	dec := json.NewDecoder(http.MaxBytesReader(r.e.Response, r.e.Request.Body, 2<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return domain.ErrInvalidParams
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return domain.ErrInvalidParams
	}
	return nil
}
func preview(r request) (any, error) {
	var input struct {
		Changes  []Change `json:"changes"`
		ZoneFile string   `json:"zoneFile"`
	}
	if err := body(r, &input); err != nil {
		return nil, err
	}
	if input.ZoneFile != "" {
		if len(input.Changes) != 0 {
			return nil, domain.ErrInvalidParams
		}
		changes, err := importZone(input.ZoneFile, r.origin)
		if err != nil {
			return nil, domain.NewError(400, err.Error())
		}
		input.Changes = changes
	}
	rows, err := zoneRecords(r.e.Request.Context(), r.client, r.s.zone, r.origin)
	if err != nil {
		return nil, err
	}
	items, pre, err := prepare(r.e.Request.Context(), r.client, r.s.provider, r.s.zone, r.origin, rows, input.Changes)
	if err != nil {
		return nil, domain.NewError(400, err.Error())
	}
	if err := r.authorize(true); err != nil {
		return nil, err
	}
	plan, err := saveNew(r.e.App.DB(), r.s, input.Changes, items)
	if err != nil {
		return nil, err
	}
	return map[string]any{"plan": plan.public(), "rows": pre}, nil
}
func search(r request) (any, error) {
	n, err := page(r)
	if err != nil {
		return nil, err
	}
	q := r.e.Request.URL.Query()
	rows, err := zoneRecords(r.e.Request.Context(), r.client, r.s.zone, r.origin)
	if err != nil {
		return nil, err
	}
	list := []dns.DNSRecord{}
	for _, row := range rows {
		if q.Get("type") != "" && !strings.EqualFold(q.Get("type"), row.Type) || q.Get("line") != "" && q.Get("line") != row.Line || q.Get("status") != "" && !strings.EqualFold(q.Get("status"), row.Status) {
			continue
		}
		word := strings.ToLower(q.Get("q"))
		if !strings.Contains(strings.ToLower(row.Name+" "+row.Content), word) {
			continue
		}
		list = append(list, row)
	}
	if group := q.Get("group"); group != "" {
		if _, ok := r.client.(Groups); !ok {
			return nil, domain.ErrInvalidParams
		}
		_, assignments, err := groupMembership(r.e.Request.Context(), r.client, r.s.zone, list)
		if err != nil {
			return nil, err
		}
		list = slices.DeleteFunc(list, func(row dns.DNSRecord) bool { return assignments[row.ID] != group })
	}
	sortField, order := q.Get("sort"), q.Get("order")
	if order != "" && order != "asc" && order != "desc" {
		return nil, domain.ErrInvalidParams
	}
	if sortField != "" {
		if !slices.Contains([]string{"name", "type", "content", "ttl", "id", "updatedAt"}, sortField) {
			return nil, domain.ErrInvalidParams
		}
		slices.SortFunc(list, func(a, b dns.DNSRecord) int {
			var d int
			switch sortField {
			case "name":
				d = strings.Compare(canonicalName(a.Name), canonicalName(b.Name))
			case "type":
				d = strings.Compare(a.Type, b.Type)
			case "content":
				d = strings.Compare(a.Content, b.Content)
			case "ttl":
				d = cmp.Compare(a.TTL, b.TTL)
			case "updatedAt":
				d = strings.Compare(a.UpdatedAt, b.UpdatedAt)
			case "id":
				d = strings.Compare(a.ID, b.ID)
			}
			if d == 0 {
				d = strings.Compare(a.ID, b.ID)
			}
			if order == "desc" {
				return -d
			}
			return d
		})
	}
	start := min((n-1)*dns.DNSPageSize, len(list))
	stop := min(start+dns.DNSPageSize, len(list))
	return dns.DNSPage[dns.DNSRecord]{Items: list[start:stop], Info: dns.PageInfo{Page: n, Total: len(list)}}, nil
}
