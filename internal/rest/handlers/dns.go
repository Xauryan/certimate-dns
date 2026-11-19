package handlers

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/internal/rest/resp"
	dnsmodel "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	cf "github.com/certimate-go/certimate/pkg/sdk3rd/cloudflare"
)

type DNSResolver func(context.Context, string, string, bool) (dnsmodel.Provider, error)
type dnsHandler struct{ resolve DNSResolver }

func BindDNS(admin, authenticated *router.RouterGroup[*core.RequestEvent], resolve DNSResolver) {
	h := dnsHandler{resolve}
	admin.GET("/dns/providers", func(e *core.RequestEvent) error { return resp.Ok(e, dnsmodel.SupportedProviders()) })
	authenticated.GET("/dns/capabilities/{provider}", func(e *core.RequestEvent) error {
		caps, ok := dnsmodel.ProviderCapabilities(e.Request.PathValue("provider"))
		if !ok {
			return resp.Err(e, domain.ErrRecordNotFound)
		}
		return resp.Ok(e, caps)
	})
	admin.GET("/dns/{provider}/{access}/zones", h.zones)
	dns := authenticated.Group("/dns/{provider}/{access}/zones/{zone}")
	dns.GET("/records", h.records)
	dns.GET("/export", h.export)
	dns.POST("/records", h.create)
	dns.PATCH("/records/{record}", h.patch)
	dns.DELETE("/records/{record}", h.remove)
}

func (h dnsHandler) client(e *core.RequestEvent, zones bool) (dnsmodel.Provider, error) {
	provider, account := e.Request.PathValue("provider"), e.Request.PathValue("access")
	if !e.HasSuperuserAuth() {
		if zones {
			return nil, domain.NewError(403, "administrator required")
		}
		if err := dnsauth.RequireZone(e, provider, account, e.Request.PathValue("zone"), e.Request.Method != http.MethodGet); err != nil {
			return nil, err
		}
	}
	return h.resolve(e.Request.Context(), provider, account, zones)
}

func pageNumber(e *core.RequestEvent) (int, error) {
	s := e.Request.URL.Query().Get("page")
	if s == "" {
		return 1, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 10000000 {
		return 0, domain.ErrInvalidParams
	}
	return n, nil
}

func dnsReply(e *core.RequestEvent, value any, err error) error {
	if errors.Is(err, cf.ErrInvalidDNSRequest) {
		err = domain.ErrInvalidParams
	}
	if err != nil {
		return resp.Err(e, err)
	}
	return resp.Ok(e, value)
}

func (h dnsHandler) zones(e *core.RequestEvent) error {
	page, err := pageNumber(e)
	if err != nil {
		return resp.Err(e, err)
	}
	c, err := h.client(e, true)
	if err != nil {
		return resp.Err(e, err)
	}
	value, err := c.Zones(e.Request.Context(), page)
	return dnsReply(e, value, err)
}

func (h dnsHandler) records(e *core.RequestEvent) error {
	page, err := pageNumber(e)
	if err != nil {
		return resp.Err(e, err)
	}
	c, err := h.client(e, false)
	if err != nil {
		return resp.Err(e, err)
	}
	value, err := c.DNSRecords(e.Request.Context(), e.Request.PathValue("zone"), page, e.Request.URL.Query().Get("name"))
	if err != nil || value == nil {
		return dnsReply(e, value, err)
	}
	edit, _ := dnsmodel.RecordEditCapabilitiesForZone(e.Request.Context(), c, e.Request.PathValue("zone"))
	return resp.Ok(e, struct {
		*dnsmodel.DNSPage[dnsmodel.DNSRecord]
		Edit dnsmodel.RecordEditCapabilities `json:"edit"`
	}{value, edit})
}

func (h dnsHandler) export(e *core.RequestEvent) error {
	c, err := h.client(e, false)
	if err != nil {
		return resp.Err(e, err)
	}
	exporter, ok := c.(interface {
		ExportDNSZone(context.Context, string) (string, error)
	})
	if !ok {
		return resp.Err(e, domain.NewError(400, "BIND export is unavailable for this provider"))
	}
	value, err := exporter.ExportDNSZone(e.Request.Context(), e.Request.PathValue("zone"))
	return dnsReply(e, value, err)
}

func validTTL(provider string, ttl int) bool {
	caps, ok := dnsmodel.ProviderCapabilities(provider)
	return ok && caps.AllowsTTL(ttl)
}
func validCreate(provider string, in dnsmodel.RecordInput) bool {
	caps, ok := dnsmodel.ProviderCapabilities(provider)
	if !ok || !caps.AllowsType(in.Type) || !caps.AllowsTTL(in.TTL) || strings.TrimSpace(in.Name) == "" || in.Content == "" {
		return false
	}
	if in.Line != "" && !caps.Line || in.Description != "" && !caps.Description || in.Weight != nil && (!caps.Weight || *in.Weight < 0) {
		return false
	}
	return in.Priority == nil || slices.Contains(caps.PriorityTypes, in.Type) && *in.Priority >= 0 && *in.Priority <= 65535
}
func finishDNSWrite(e *core.RequestEvent, id string, err error) error {
	e.App.Logger().Info("DNS record operation", "method", e.Request.Method, "actor", e.Auth.Id, "access", e.Request.PathValue("access"), "zone", e.Request.PathValue("zone"), "record", id, "success", err == nil)
	return dnsReply(e, id, err)
}

func (h dnsHandler) create(e *core.RequestEvent) error {
	var input cf.RecordInput
	if err := e.BindBody(&input); err != nil || !validCreate(e.Request.PathValue("provider"), input) {
		return resp.Err(e, domain.ErrInvalidParams)
	}
	c, err := h.client(e, false)
	if err != nil {
		return resp.Err(e, err)
	}
	id, err := c.CreateDNSRecord(e.Request.Context(), e.Request.PathValue("zone"), input)
	return finishDNSWrite(e, id, err)
}

func (h dnsHandler) patch(e *core.RequestEvent) error {
	var input recordUpdate
	if err := e.BindBody(&input); err != nil || input.Content == "" || !validTTL(e.Request.PathValue("provider"), input.TTL) {
		return resp.Err(e, domain.ErrInvalidParams)
	}
	c, err := h.client(e, false)
	if err != nil {
		return resp.Err(e, err)
	}
	id := e.Request.PathValue("record")
	if input.Expected != nil || input.Name != nil || input.Type != nil || input.Priority != nil {
		id, err = replaceRecord(e, c, id, input)
	} else {
		id, err = c.PatchDNSRecord(e.Request.Context(), e.Request.PathValue("zone"), id, input.RecordPatch)
	}
	return finishDNSWrite(e, id, err)
}

func (h dnsHandler) remove(e *core.RequestEvent) error {
	c, err := h.client(e, false)
	if err != nil {
		return resp.Err(e, err)
	}
	id := e.Request.PathValue("record")
	_, err = c.DeleteDNSRecord(e.Request.Context(), e.Request.PathValue("zone"), id)
	return finishDNSWrite(e, id, err)
}
