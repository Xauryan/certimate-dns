package ddnsfleet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
)

type Service struct {
	resolve   Resolver
	mutations sync.Mutex
	now       func() time.Time
}

func New(resolve Resolver) *Service {
	return &Service{resolve: resolve, now: time.Now}
}

func (s *Service) Bind(api *router.RouterGroup[*core.RequestEvent]) {
	ddns := api.Group("/ddns").Unbind(apis.DefaultBodyLimitMiddlewareId)
	ddns.POST("/report", s.handleReport).
		Unbind(apis.DefaultLoadAuthTokenMiddlewareId).
		BindFunc(limitBody(maxReportBytes))
	admin := ddns.Group("").Bind(apis.RequireSuperuserAuth()).BindFunc(limitBody(4 << 10))
	admin.GET("/nodes", s.listNodes)
	admin.POST("/nodes", s.createNode)
	admin.PATCH("/nodes/{id}", s.updateNode)
	admin.POST("/nodes/{id}/rotate", s.rotateNode)
	admin.DELETE("/nodes/{id}", s.deleteNode)
	s.bindBindingRoutes(admin)
}

func limitBody(maxBytes int64) func(*core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		if e.Request.ContentLength > maxBytes {
			return e.Error(http.StatusRequestEntityTooLarge, "DDNS request is too large.", nil)
		}
		e.Request.Body = http.MaxBytesReader(e.Response, e.Request.Body, maxBytes)
		return e.Next()
	}
}

func decodeBody(e *core.RequestEvent, value any) error {
	raw, err := io.ReadAll(e.Request.Body)
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return e.Error(http.StatusRequestEntityTooLarge, "DDNS request is too large.", nil)
	}
	if err != nil || !utf8.Valid(raw) {
		return e.BadRequestError("Invalid DDNS request.", nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return e.BadRequestError("Invalid DDNS request.", nil)
	}
	return nil
}

func (s *Service) Run(ctx context.Context, app core.App) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.syncOnlineNodes(ctx, app); err != nil && ctx.Err() == nil {
				app.Logger().Error("DDNS device synchronization scan failed.")
			}
		}
	}
}

func (s *Service) syncOnlineNodes(ctx context.Context, app core.App) error {
	var nodes []struct {
		ID string `db:"id"`
	}
	err := app.DB().Select("ddns_nodes.id").
		From("ddns_nodes").
		Where(dbx.HashExp{"enabled": true, "report_required": false}).
		AndWhere(dbx.NewExp("seen_at >= {:since}", dbx.Params{"since": s.now().Add(-onlineWindow).Unix()})).
		AndWhere(dbx.NewExp("EXISTS (SELECT 1 FROM ddns_bindings WHERE node_id=ddns_nodes.id)")).
		OrderBy("ddns_nodes.id").WithContext(ctx).All(&nodes)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.syncActiveNode(ctx, app, node.ID)
	}
	return nil
}

func (s *Service) syncActiveNode(ctx context.Context, app core.App, nodeID string) {
	if ctx.Err() != nil {
		return
	}
	var snapshot string
	err := app.DB().Select("interfaces").From("ddns_nodes").
		Where(dbx.HashExp{"id": nodeID, "enabled": true, "report_required": false}).
		AndWhere(dbx.NewExp("seen_at >= {:since}", dbx.Params{"since": s.now().Add(-onlineWindow).Unix()})).
		WithContext(ctx).Row(&snapshot)
	var interfaces []Interface
	if err != nil || json.Unmarshal([]byte(snapshot), &interfaces) != nil {
		return
	}
	s.syncNode(ctx, app, nodeID, interfaces)
}
