// Package dnsadvanced exposes optional zone capabilities through the application's
// existing DNS account resolver and live zone permissions.
package dnsadvanced

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/dnscheck"
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/internal/rest/resp"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
)

type Resolver func(context.Context, string, string, bool) (dns.Provider, error)

type detailsProvider interface {
	ZoneDetails(context.Context, string) (*dns.ZoneDetails, error)
}
type aliasProvider interface {
	DomainAliases(context.Context, string) ([]dns.DomainAlias, error)
	AddDomainAlias(context.Context, string, string) error
	DeleteDomainAlias(context.Context, string, string) error
}
type weightProvider interface {
	WeightRules(context.Context, string, int, string) (*dns.DNSPage[dns.WeightRule], error)
	SetWeightRule(context.Context, string, dns.WeightRule) error
}

type call struct {
	e    *core.RequestEvent
	ctx  context.Context
	zone dnsauth.Zone
	p    dns.Provider
}
type operation func(call) (any, error)

func Bind(api *router.RouterGroup[*core.RequestEvent], resolve Resolver) {
	g := api.Group("/dns/{provider}/{access}/zones/{zone}/advanced")
	wrap := func(write bool, fn operation) func(*core.RequestEvent) error {
		return func(e *core.RequestEvent) error {
			z, err := dnsauth.FindZone(e, e.Request.PathValue("provider"), e.Request.PathValue("access"), e.Request.PathValue("zone"), write)
			if err != nil {
				return resp.Err(e, err)
			}
			ctx := e.Request.Context()
			p, err := resolve(ctx, z.Provider, z.AccessID, false)
			if err != nil {
				return resp.Err(e, domain.NewError(400, "could not open DNS provider"))
			}
			if write {
				if err := dnsauth.RequireZone(e, z.Provider, z.AccessID, z.ZoneID, true); err != nil {
					return resp.Err(e, err)
				}
			}
			out, err := fn(call{e: e, ctx: ctx, zone: z, p: p})
			if write {
				e.App.Logger().Info("advanced DNS change", "actor", e.Auth.Id, "zone", z.ID, "method", e.Request.Method, "success", err == nil)
			}
			e.Response.Header().Set("Cache-Control", "no-store")
			var known *domain.Error
			switch {
			case err == nil:
				return resp.Ok(e, out)
			case errors.As(err, &known):
				return resp.Err(e, known)
			case errors.Is(err, dns.ErrInvalidDNSRequest):
				return resp.Err(e, domain.ErrInvalidParams)
			default:
				return resp.Err(e, domain.NewError(502, "DNS provider did not complete the operation"))
			}
		}
	}
	g.GET("/features", wrap(false, func(r call) (any, error) {
		_, details := r.p.(detailsProvider)
		_, aliases := r.p.(aliasProvider)
		_, weights := r.p.(weightProvider)
		return map[string]bool{"details": details, "aliases": aliases, "weights": weights}, nil
	}))
	g.GET("/records/{id}/check", wrap(false, checkRecord))
	g.GET("/details", wrap(false, func(r call) (any, error) {
		p, ok := r.p.(detailsProvider)
		if !ok {
			return nil, unavailable
		}
		return p.ZoneDetails(r.ctx, r.zone.ZoneID)
	}))
	g.GET("/aliases", wrap(false, func(r call) (any, error) {
		p, ok := r.p.(aliasProvider)
		if !ok {
			return nil, unavailable
		}
		return p.DomainAliases(r.ctx, r.zone.ZoneID)
	}))
	g.POST("/aliases", wrap(true, func(r call) (any, error) {
		p, ok := r.p.(aliasProvider)
		if !ok {
			return nil, unavailable
		}
		var body struct {
			Name string `json:"name"`
		}
		if err := decode(r.e, &body); err != nil || body.Name == "" || len(body.Name) > 253 {
			return nil, domain.ErrInvalidParams
		}
		return nil, p.AddDomainAlias(r.ctx, r.zone.ZoneID, body.Name)
	}))
	g.DELETE("/aliases/{id}", wrap(true, func(r call) (any, error) {
		p, ok := r.p.(aliasProvider)
		if !ok {
			return nil, unavailable
		}
		return nil, p.DeleteDomainAlias(r.ctx, r.zone.ZoneID, r.e.Request.PathValue("id"))
	}))
	g.GET("/weights", wrap(false, func(r call) (any, error) {
		p, ok := r.p.(weightProvider)
		if !ok {
			return nil, unavailable
		}
		q := r.e.Request.URL.Query()
		page, err := pageNumber(q.Get("page"))
		if err != nil || len(q.Get("name")) > 253 {
			return nil, domain.ErrInvalidParams
		}
		return p.WeightRules(r.ctx, r.zone.ZoneID, page, q.Get("name"))
	}))
	g.PUT("/weights", wrap(true, func(r call) (any, error) {
		p, ok := r.p.(weightProvider)
		if !ok {
			return nil, unavailable
		}
		var body struct {
			Name    string `json:"name"`
			Type    string `json:"type"`
			Line    string `json:"line"`
			Enabled *bool  `json:"enabled"`
		}
		if err := decode(r.e, &body); err != nil || body.Enabled == nil || len(body.Name) > 253 || strings.TrimSpace(body.Name) == "" || len(body.Line) > 128 {
			return nil, domain.ErrInvalidParams
		}
		return nil, p.SetWeightRule(r.ctx, r.zone.ZoneID, dns.WeightRule{Name: body.Name, Type: body.Type, Line: body.Line, Enabled: *body.Enabled})
	}))
}

var unavailable = domain.NewError(400, "DNS provider does not support this operation")

func decode(e *core.RequestEvent, out any) error {
	dec := json.NewDecoder(http.MaxBytesReader(e.Response, e.Request.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return domain.ErrInvalidParams
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return domain.ErrInvalidParams
	}
	return nil
}
func pageNumber(s string) (int, error) {
	if s == "" {
		return 1, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 1000000 {
		return 0, domain.ErrInvalidParams
	}
	return n, nil
}

// Re-read the displayed page and match the selected ID before issuing a DNS
// query. A stale page forces the caller to refresh instead of probing another name.
func checkRecord(r call) (any, error) {
	q := r.e.Request.URL.Query()
	page, err := pageNumber(q.Get("page"))
	if err != nil || len(q.Get("name")) > 253 {
		return nil, domain.ErrInvalidParams
	}
	rows, err := r.p.DNSRecords(r.ctx, r.zone.ZoneID, page, q.Get("name"))
	if err != nil {
		return nil, err
	}
	if rows == nil || rows.Info.Page != page {
		return nil, domain.ErrRecordNotFound
	}
	for _, rec := range rows.Items {
		if rec.ID == r.e.Request.PathValue("id") {
			res, err := dnscheck.Check(r.ctx, r.zone.Name, rec.Name, rec.Type, rec.Content)
			if errors.Is(err, dnscheck.ErrInvalid) {
				return nil, domain.ErrInvalidParams
			}
			if errors.Is(err, dnscheck.ErrResolver) {
				return nil, domain.NewError(502, "DNS resolver did not return a complete answer")
			}
			return res, err
		}
	}
	return nil, domain.ErrRecordNotFound
}
