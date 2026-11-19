package dnsproxysettings

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
)

const probeURL = "https://dl.amh.sh/ip.htm"

func decode(e *core.RequestEvent, v any) error {
	d := json.NewDecoder(e.Request.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return e.BadRequestError("Invalid DNS proxy request.", nil)
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		return e.BadRequestError("Invalid DNS proxy request.", nil)
	}
	return nil
}

// Bind registers superuser-only DNS proxy settings under the /api group.
// The probe uses the same transport constructor as provider calls.
func Bind(api *router.RouterGroup[*core.RequestEvent], newTransport func(*url.URL) (*http.Transport, error)) {
	g := api.Group("/dns-proxy").Bind(apis.RequireSuperuserAuth(), apis.BodyLimit(4<<10))
	g.GET("/settings", func(e *core.RequestEvent) error {
		v, err := settingsView(e.App)
		if err != nil {
			return e.InternalServerError("Could not read DNS proxy settings.", nil)
		}
		e.Response.Header().Set("Cache-Control", "no-store")
		return e.JSON(200, v)
	})
	g.PUT("/settings", func(e *core.RequestEvent) error {
		var v input
		if err := decode(e, &v); err != nil {
			return err
		}
		if err := save(e.App, v); err != nil {
			if errors.Is(err, errInvalid) {
				return e.BadRequestError("Invalid DNS proxy endpoint or credentials.", nil)
			}
			return e.InternalServerError("Could not save DNS proxy settings.", nil)
		}
		e.App.Logger().Info("Updated DNS proxy settings", "actor", e.Auth.Id, "enabled", *v.Enabled)
		return e.NoContent(204)
	})
	g.POST("/test", func(e *core.RequestEvent) error {
		if err := decode(e, &struct{}{}); err != nil {
			return err
		}
		r, err := read(e.App)
		if err != nil {
			return e.InternalServerError("Could not read DNS proxy settings.", nil)
		}
		u, err := r.proxyURL(e.App)
		if err != nil {
			return e.InternalServerError("Could not read DNS proxy settings.", nil)
		}
		if u == nil {
			return e.BadRequestError("Configure a DNS proxy first.", nil)
		}
		tr, err := newTransport(u)
		if err != nil || tr == nil {
			return e.Error(502, "DNS proxy test failed.", nil)
		}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, err := http.NewRequestWithContext(e.Request.Context(), http.MethodGet, probeURL, nil)
		if err != nil {
			return e.InternalServerError("Could not prepare DNS proxy test.", nil)
		}
		start := time.Now()
		res, err := client.Do(req)
		if err != nil {
			return e.Error(502, "DNS proxy test failed.", nil)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return e.Error(502, "DNS proxy test failed.", nil)
		}
		return e.JSON(200, map[string]any{"ok": true, "latencyMs": time.Since(start).Milliseconds()})
	})
}
