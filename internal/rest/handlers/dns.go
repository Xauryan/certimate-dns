package handlers

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"

	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/internal/rest/resp"
	cf "github.com/certimate-go/certimate/pkg/sdk3rd/cloudflare"
)

type dnsAccessReader interface {
	GetById(context.Context, string) (*domain.Access, error)
}

type dnsHandler struct{ accesses dnsAccessReader }

func BindDNS(group *router.RouterGroup[*core.RequestEvent], accesses dnsAccessReader) {
	h := dnsHandler{accesses: accesses}
	dns := group.Group("/dns/cloudflare/{access}")
	dns.GET("/zones", h.zones)
	records := "/zones/{zone}/records"
	dns.GET(records, h.records)
	dns.GET("/zones/{zone}/export", h.export)
	dns.POST(records, h.create)
	dns.PATCH(records+"/{record}", h.patch)
	dns.DELETE(records+"/{record}", h.remove)
}

func (h dnsHandler) client(e *core.RequestEvent, zones bool) (*cf.Client, error) {
	a, err := h.accesses.GetById(e.Request.Context(), e.Request.PathValue("access"))
	if domain.IsRecordNotFoundError(err) {
		return nil, err
	}
	if err != nil {
		return nil, errors.New("could not read DNS account")
	}
	if a.Provider != "cloudflare" {
		return nil, domain.ErrInvalidParams
	}
	token, _ := a.Config["apiToken"].(string)
	if zoneToken, _ := a.Config["apiTokenForZone"].(string); zones && zoneToken != "" {
		token = zoneToken
	}
	client, err := cf.NewClient(cf.WithApiToken(token))
	if err != nil {
		return nil, domain.NewError(400, "missing Cloudflare token")
	}
	return client.SetTimeout(25 * time.Second), nil
}

func pageNumber(e *core.RequestEvent) (int, error) {
	s := e.Request.URL.Query().Get("page")
	if s == "" {
		return 1, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
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
	return dnsReply(e, value, err)
}

func (h dnsHandler) export(e *core.RequestEvent) error {
	c, err := h.client(e, false)
	if err != nil {
		return resp.Err(e, err)
	}
	value, err := c.ExportDNSZone(e.Request.Context(), e.Request.PathValue("zone"))
	return dnsReply(e, value, err)
}

func validTTL(ttl int) bool { return ttl == 1 || (ttl >= 30 && ttl <= 86400) }

func finishDNSWrite(e *core.RequestEvent, id string, err error) error {
	e.App.Logger().Info("DNS record operation", "method", e.Request.Method, "actor", e.Auth.Id, "access", e.Request.PathValue("access"), "zone", e.Request.PathValue("zone"), "record", id, "success", err == nil)
	return dnsReply(e, id, err)
}

func (h dnsHandler) create(e *core.RequestEvent) error {
	var input cf.RecordInput
	if err := e.BindBody(&input); err != nil || strings.TrimSpace(input.Name) == "" || input.Content == "" || !validTTL(input.TTL) {
		return resp.Err(e, domain.ErrInvalidParams)
	}
	switch input.Type {
	case "A", "AAAA", "CNAME", "TXT":
	default:
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
	var input cf.RecordPatch
	if err := e.BindBody(&input); err != nil || input.Content == "" || !validTTL(input.TTL) {
		return resp.Err(e, domain.ErrInvalidParams)
	}
	c, err := h.client(e, false)
	if err != nil {
		return resp.Err(e, err)
	}
	id := e.Request.PathValue("record")
	_, err = c.PatchDNSRecord(e.Request.Context(), e.Request.PathValue("zone"), id, input)
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
