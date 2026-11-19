package dnsoptimize

import (
	"context"
	"time"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"

	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/internal/rest/resp"
)

type request struct {
	Spec     Spec   `json:"spec"`
	Interval int    `json:"interval"`
	Digest   string `json:"digest"`
}

func target(e *core.RequestEvent) Target {
	return Target{e.Request.PathValue("provider"), e.Request.PathValue("access"), e.Request.PathValue("zone")}
}
func (s *Service) Bind(group *router.RouterGroup[*core.RequestEvent]) {
	g := group.Group("/dns/{provider}/{access}/zones/{zone}/optimize")
	g.Bind(apis.RequireSuperuserAuth(), apis.BodyLimit(16<<10))
	g.GET("/quota", func(e *core.RequestEvent) error {
		ctx := e.Request.Context()
		if err := s.authorize(ctx, target(e)); err != nil {
			return resp.Err(e, err)
		}
		quota, err := s.Quota(ctx, e.Request.URL.Query().Get("source"))
		return reply(e, quota, err)
	})
	g.POST("/tasks/{id}/run", func(e *core.RequestEvent) error {
		var in request
		if e.BindBody(&in) != nil {
			return resp.Err(e, domain.ErrInvalidParams)
		}
		ctx, cancel := context.WithTimeout(e.Request.Context(), 90*time.Second)
		defer cancel()
		plan, err := s.RunTask(ctx, target(e), e.Request.PathValue("id"), e.Auth.Id, in.Digest)
		return reply(e, plan, err)
	})
	g.GET("/candidates", s.candidates)
	g.POST("/preview", s.plan)
	g.POST("/apply", s.execute)
	g.GET("/tasks", s.list)
	g.POST("/tasks", s.save)
	g.PUT("/tasks/{id}", s.save)
	g.POST("/tasks/{id}/state", s.state)
	g.DELETE("/tasks/{id}", s.remove)
	g.GET("/history", s.history)
}
func reply(e *core.RequestEvent, v any, err error) error {
	if err != nil {
		return resp.Err(e, err)
	}
	return resp.Ok(e, v)
}
func (s *Service) authorize(ctx context.Context, t Target) error {
	if providerLines[t.Provider] == nil {
		return domain.ErrInvalidParams
	}
	_, err := catalogName(ctx, s.app, t)
	return err
}
func (s *Service) candidates(e *core.RequestEvent) error {
	ctx := e.Request.Context()
	if err := s.authorize(ctx, target(e)); err != nil {
		return resp.Err(e, err)
	}
	q := e.Request.URL.Query()
	data, err := s.addresses(ctx, Feed{q.Get("source"), q.Get("cdn"), q.Get("family")})
	return reply(e, data, err)
}
func (s *Service) plan(e *core.RequestEvent) error {
	var in request
	if err := e.BindBody(&in); err != nil {
		return resp.Err(e, domain.ErrInvalidParams)
	}
	ctx, cancel := context.WithTimeout(e.Request.Context(), 90*time.Second)
	defer cancel()
	_, plan, err := s.preview(ctx, target(e), in.Spec)
	return reply(e, plan, err)
}
func (s *Service) execute(e *core.RequestEvent) error {
	var in request
	if err := e.BindBody(&in); err != nil || len(in.Digest) != 64 {
		return resp.Err(e, domain.ErrInvalidParams)
	}
	ctx, cancel := context.WithTimeout(e.Request.Context(), 90*time.Second)
	defer cancel()
	if err := s.lock(ctx); err != nil {
		return resp.Err(e, err)
	}
	defer s.unlock()
	plan, err := s.apply(ctx, target(e), in.Spec, in.Digest, "", e.Auth.Id)
	return reply(e, plan, err)
}
func (s *Service) list(e *core.RequestEvent) error {
	ctx, t := e.Request.Context(), target(e)
	if err := s.authorize(ctx, t); err != nil {
		return resp.Err(e, err)
	}
	rows, err := listTasks(ctx, s.app, t)
	return reply(e, rows, err)
}
func (s *Service) save(e *core.RequestEvent) error {
	var in request
	if err := e.BindBody(&in); err != nil {
		return resp.Err(e, domain.ErrInvalidParams)
	}
	ctx, t := e.Request.Context(), target(e)
	if err := s.authorize(ctx, t); err != nil {
		return resp.Err(e, err)
	}
	id, err := SaveConfig(ctx, s.app, t, in.Spec, in.Interval, e.Request.PathValue("id"))
	return reply(e, id, err)
}
func (s *Service) state(e *core.RequestEvent) error {
	var in struct {
		Enabled *bool  `json:"enabled"`
		Digest  string `json:"digest"`
	}
	if err := e.BindBody(&in); err != nil || in.Enabled == nil {
		return resp.Err(e, domain.ErrInvalidParams)
	}
	ctx, cancel := context.WithTimeout(e.Request.Context(), 90*time.Second)
	defer cancel()
	t, id := target(e), e.Request.PathValue("id")
	return reply(e, id, s.SetEnabled(ctx, t, id, *in.Enabled, in.Digest))
}
func (s *Service) remove(e *core.RequestEvent) error {
	ctx, t := e.Request.Context(), target(e)
	if err := s.authorize(ctx, t); err != nil {
		return resp.Err(e, err)
	}
	return reply(e, nil, DeleteDraft(ctx, s.app, t, e.Request.PathValue("id")))
}
func (s *Service) history(e *core.RequestEvent) error {
	ctx, t := e.Request.Context(), target(e)
	if err := s.authorize(ctx, t); err != nil {
		return resp.Err(e, err)
	}
	rows := []struct {
		ID       int64  `db:"id" json:"id"`
		Task     string `db:"task" json:"task"`
		Actor    string `db:"actor" json:"actor"`
		Started  int64  `db:"started" json:"started"`
		Snapshot string `db:"plan" json:"snapshot"`
		Status   string `db:"status" json:"status"`
	}{}
	err := s.app.DB().NewQuery("SELECT id,task,actor,started,plan,status FROM dns_optimize_runs WHERE " + scoped + " ORDER BY id DESC LIMIT 100").WithContext(ctx).Bind(t.params()).All(&rows)
	if err != nil {
		return resp.Err(e, domain.NewError(500, "could not read optimization history"))
	}
	return resp.Ok(e, rows)
}
