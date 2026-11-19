// Package cfmanagement exposes typed Cloudflare control-plane operations using
// the selected Certimate access record and the current administrator session.
package cfmanagement

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"

	"github.com/certimate-go/certimate/internal/dnscatalog"
	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	managed "github.com/certimate-go/certimate/internal/dnsmanagement"
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/internal/rest/resp"
	cf "github.com/certimate-go/certimate/pkg/sdk3rd/cloudflare"
)

var validAccountID = regexp.MustCompile("^[0-9a-f]{32}$")

type accessReader interface {
	GetById(context.Context, string) (*domain.Access, error)
}

type operation struct {
	*cf.Client
	zoneReader                      *cf.Client
	ctx                             context.Context
	zone, account, tunnel, kind, id string
	pinnedAccount                   string
	method                          string
	page                            int
}

func withAccess(accesses accessReader, handle func(operation, *core.RequestEvent) (any, error)) func(*core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		ctx := e.Request.Context()
		e.Response.Header().Set("Cache-Control", "no-store")
		accessID := e.Request.PathValue("access")
		enabled, err := dnscatalog.IsEnabled(e.App, accessID)
		if err != nil {
			return resp.Err(e, domain.NewError(500, "could not verify DNS account status"))
		}
		if !enabled {
			return resp.Err(e, domain.ErrRecordNotFound)
		}
		a, err := accesses.GetById(ctx, accessID)
		if err != nil || a == nil || a.Provider != "cloudflare" || a.DeletedAt != nil {
			return resp.Err(e, domain.ErrRecordNotFound)
		}
		field := func(key string) string { v, _ := a.Config[key].(string); return strings.TrimSpace(v) }
		pinned := field("accountId")
		if pinned != "" && !validAccountID.MatchString(pinned) {
			return resp.Err(e, domain.ErrInvalidParams)
		}
		account, zone := e.Request.PathValue("account"), e.Request.PathValue("zone")
		if pinned != "" && account != "" && pinned != account {
			return resp.Err(e, domain.ErrRecordNotFound)
		}
		global := field("authMethod") == "globalapikey"
		if zone == "" && global {
			return resp.Err(e, domain.NewError(400, "Cloudflare Tunnel requires API token authentication"))
		}
		opt := cf.WithApiToken(field("apiToken"))
		if global {
			opt = cf.WithGlobalAPIKey(field("email"), field("apiKey"))
		}
		a, err = managed.WithAccountTransport(e.App, a)
		if err != nil {
			return resp.Err(e, err)
		}
		transport := cf.WithDNSTransport(dnsutil.TransportFor(a))
		accountScope := cf.WithAccountID(pinned)
		client, err := cf.NewClient(opt, accountScope, transport)
		if err != nil {
			return resp.Err(e, domain.NewError(400, "invalid Cloudflare credential"))
		}
		zoneReader := client
		if token := field("apiTokenForZone"); !global && token != "" {
			zoneReader, err = cf.NewClient(cf.WithApiToken(token), accountScope, transport)
			if err != nil {
				return resp.Err(e, domain.ErrInvalidParams)
			}
		}
		client.SetTimeout(25 * time.Second)
		zoneReader.SetTimeout(25 * time.Second)
		if zone != "" && pinned != "" {
			owner, err := zoneReader.ZoneAccount(ctx, zone)
			if err != nil || owner.ID != pinned {
				return resp.Err(e, domain.ErrRecordNotFound)
			}
		}
		page := 1
		if raw := e.Request.URL.Query().Get("page"); raw != "" {
			page, err = strconv.Atoi(raw)
			if err != nil || page < 1 || page > 10000000 {
				return resp.Err(e, domain.ErrInvalidParams)
			}
		}
		param := e.Request.PathValue
		op := operation{pinnedAccount: pinned, zoneReader: zoneReader, Client: client, ctx: ctx, zone: param("zone"), account: param("account"), tunnel: param("tunnel"), kind: param("kind"), id: param("id"), page: page, method: e.Request.Method}
		data, err := handle(op, e)
		if op.method != http.MethodGet {
			e.App.Logger().Info("Cloudflare management operation", "actor", e.Auth.Id, "route", e.Request.Pattern, "access", a.Id, "success", err == nil)
		}
		if err != nil {
			var upstream *cf.ProviderStatusError
			switch {
			case errors.Is(err, cf.ErrInvalidDNSRequest):
				err = domain.ErrInvalidParams
			case errors.Is(err, cf.ErrConfigChanged):
				err = domain.NewError(409, err.Error())
			case errors.As(err, &upstream):
				err = domain.NewError(upstream.Status, upstream.Error())
			}
			return resp.Err(e, err)
		}
		e.Response.Header().Set("Cache-Control", "no-store")
		return resp.Ok(e, data)
	}
}

func body[T any](e *core.RequestEvent) (T, error) {
	var in T
	d := json.NewDecoder(e.Request.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&in); err != nil {
		return in, domain.ErrInvalidParams
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return in, domain.ErrInvalidParams
	}
	return in, nil
}

func Bind(group *router.RouterGroup[*core.RequestEvent], accesses accessReader) {
	api := group.Group("/cloudflare/{access}").Bind(apis.RequireSuperuserAuth(), apis.BodyLimit(32<<10))
	bind := func(handle func(operation, *core.RequestEvent) (any, error)) func(*core.RequestEvent) error {
		return withAccess(accesses, handle)
	}
	api.GET("/accounts", bind(func(op operation, _ *core.RequestEvent) (any, error) {
		if op.pinnedAccount != "" {
			page := cf.DNSPage[cf.AccountSummary]{Items: []cf.AccountSummary{}, Info: cf.PageInfo{Page: op.page, Total: 1}}
			if op.page == 1 {
				page.Items = []cf.AccountSummary{{ID: op.pinnedAccount, Name: op.pinnedAccount}}
			}
			return page, nil
		}
		return op.Accounts(op.ctx, op.page)
	}))
	saas := api.Group("/zones/{zone}")
	saas.GET("/targets", bind(func(op operation, e *core.RequestEvent) (any, error) {
		if _, err := op.zoneReader.ZoneAccount(op.ctx, op.zone); err != nil {
			return nil, err
		}
		return targetZones(e, e.Request.URL.Query().Get("name"))
	}))
	saas.GET("/hostnames", bind(func(op operation, _ *core.RequestEvent) (any, error) { return op.Hostnames(op.ctx, op.zone, op.page) }))
	save := bind(func(op operation, e *core.RequestEvent) (any, error) {
		in, err := body[cf.HostnameInput](e)
		if err != nil {
			return nil, err
		}
		return op.SaveHostname(op.ctx, op.zone, op.id, in)
	})
	saas.POST("/hostnames", save)
	saas.PATCH("/hostnames/{id}", save)
	saas.POST("/hostnames/{id}/revalidate", bind(func(op operation, _ *core.RequestEvent) (any, error) {
		return op.RevalidateHostname(op.ctx, op.zone, op.id)
	}))
	saas.DELETE("/hostnames/{id}", bind(func(op operation, _ *core.RequestEvent) (any, error) {
		return nil, op.DeleteHostname(op.ctx, op.zone, op.id)
	}))
	fallback := bind(func(op operation, e *core.RequestEvent) (any, error) {
		var origin string
		if op.method == http.MethodPut {
			in, err := body[struct {
				Origin string `json:"origin"`
			}](e)
			if err != nil {
				return nil, err
			}
			origin = in.Origin
		}
		return op.FallbackOrigin(op.ctx, op.zone, op.method, origin)
	})
	saas.GET("/fallback", fallback)
	saas.PUT("/fallback", fallback)
	saas.DELETE("/fallback", fallback)
	saas.GET("/dcv", bind(func(op operation, _ *core.RequestEvent) (any, error) { return op.Delegation(op.ctx, op.zone) }))
	tunnels := api.Group("/accounts/{account}/tunnels")
	tunnels.GET("", bind(func(op operation, _ *core.RequestEvent) (any, error) { return op.Tunnels(op.ctx, op.account, op.page) }))
	tunnels.POST("", bind(func(op operation, e *core.RequestEvent) (any, error) {
		in, err := body[struct {
			Name string `json:"name"`
		}](e)
		if err != nil {
			return nil, err
		}
		return op.CreateTunnel(op.ctx, op.account, in.Name)
	}))
	tunnels.POST("/{tunnel}/connector", bind(func(op operation, e *core.RequestEvent) (any, error) {
		in, err := body[struct {
			Recipient string `json:"publicKey"`
		}](e)
		if err != nil {
			return nil, err
		}
		return op.EncryptedTunnelToken(op.ctx, op.account, op.tunnel, in.Recipient)
	}))
	tunnels.PATCH("/{tunnel}", bind(func(op operation, e *core.RequestEvent) (any, error) {
		in, err := body[struct {
			Name string `json:"name"`
		}](e)
		if err != nil {
			return nil, err
		}
		return op.EditTunnel(op.ctx, op.account, op.tunnel, in.Name)
	}))
	tunnels.DELETE("/{tunnel}", bind(func(op operation, _ *core.RequestEvent) (any, error) {
		return nil, op.DeleteTunnel(op.ctx, op.account, op.tunnel)
	}))
	routes := tunnels.Group("/{tunnel}/routes/{kind}")
	routes.GET("", bind(func(op operation, _ *core.RequestEvent) (any, error) {
		return op.TunnelRoutes(op.ctx, op.account, op.tunnel, op.kind, op.page)
	}))
	routes.POST("", bind(func(op operation, e *core.RequestEvent) (any, error) {
		in, err := body[cf.RouteInput](e)
		if err != nil {
			return nil, err
		}
		return op.AddRoute(op.ctx, op.account, op.tunnel, op.kind, in)
	}))
	routes.DELETE("/{id}", bind(func(op operation, _ *core.RequestEvent) (any, error) {
		return nil, op.DeleteRoute(op.ctx, op.account, op.tunnel, op.kind, op.id)
	}))
	published := tunnels.Group("/{tunnel}/published")
	published.GET("", bind(func(op operation, _ *core.RequestEvent) (any, error) {
		return op.PublishedRoutes(op.ctx, op.account, op.tunnel)
	}))
	edit := bind(func(op operation, e *core.RequestEvent) (any, error) {
		in, err := body[cf.IngressChange](e)
		if err != nil {
			return nil, err
		}
		return nil, op.ChangeIngressWithZoneReader(op.ctx, op.account, op.tunnel, in, op.method == http.MethodDelete, op.zoneReader)
	})
	published.PUT("", edit)
	published.DELETE("", edit)
}
