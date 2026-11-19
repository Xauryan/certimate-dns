package dnsautomation

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/certimate-go/certimate/internal/rest/resp"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
)

func reply(e *core.RequestEvent, data any, err error) error {
	if err == nil {
		return resp.Ok(e, data)
	}
	code, msg := publicError(err)
	return e.JSON(code, map[string]any{"code": code, "message": msg, "msg": msg})
}
func pageNum(e *core.RequestEvent) (int, error) {
	p := e.Request.URL.Query().Get("page")
	if p == "" {
		return 1, nil
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 1000000 {
		return 0, errInput
	}
	return n, nil
}

func Bind(group *router.RouterGroup[*core.RequestEvent], s *Service) {
	g := group.Group("/dns-automation")
	g.Bind(apis.RequireSuperuserAuth())
	g.GET("/heartbeat", func(e *core.RequestEvent) error { return resp.Ok(e, map[string]int64{"lastTick": s.LastTick()}) })
	g.GET("", func(e *core.RequestEvent) error {
		page, err := pageNum(e)
		if err != nil {
			return reply(e, nil, err)
		}
		items, count, err := s.List(e.Request.Context(), page)
		return reply(e, map[string]any{"items": items, "total": count}, err)
	})
	g.POST("", func(e *core.RequestEvent) error {
		var d Definition
		e.Request.Body = http.MaxBytesReader(e.Response, e.Request.Body, 16384)
		if e.BindBody(&d) != nil {
			return reply(e, nil, errInput)
		}
		t, err := s.Create(e.Request.Context(), e.Auth.Id, d)
		return reply(e, t, err)
	})
	g.GET("/{id}", func(e *core.RequestEvent) error {
		t, err := getTask(e.Request.Context(), s.app, e.Request.PathValue("id"))
		return reply(e, t, err)
	})
	g.GET("/{id}/history", func(e *core.RequestEvent) error {
		page, err := pageNum(e)
		if err != nil {
			return reply(e, nil, err)
		}
		items, count, err := s.History(e.Request.Context(), e.Request.PathValue("id"), page)
		return reply(e, map[string]any{"items": items, "total": count}, err)
	})
	g.PUT("/{id}", func(e *core.RequestEvent) error {
		var req struct {
			Version    int
			Definition Definition
		}
		e.Request.Body = http.MaxBytesReader(e.Response, e.Request.Body, 16384)
		if e.BindBody(&req) != nil {
			return reply(e, nil, errInput)
		}
		err := s.Edit(e.Request.Context(), e.Request.PathValue("id"), e.Auth.Id, req.Version, req.Definition)
		return reply(e, nil, err)
	})
	g.POST("/{id}/{action}", func(e *core.RequestEvent) error {
		var req struct{ Version int }
		e.Request.Body = http.MaxBytesReader(e.Response, e.Request.Body, 1024)
		if e.BindBody(&req) != nil || req.Version < 1 {
			return reply(e, nil, errInput)
		}
		ctx, cancel := context.WithTimeout(e.Request.Context(), 120*time.Second)
		defer cancel()
		err := s.control(ctx, e.Request.PathValue("id"), e.Auth.Id, e.Request.PathValue("action"), req.Version)
		return reply(e, nil, err)
	})
}
