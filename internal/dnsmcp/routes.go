package dnsmcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/dnsautomation"
	"github.com/certimate-go/certimate/internal/dnscert"
	"github.com/certimate-go/certimate/internal/dnsoptimize"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

const bodyLimit = 256 << 10

type object = map[string]any
type resolver = func(context.Context, string, string, bool) (dns.Provider, error)
type Services struct {
	Deploy     DeploymentFunc
	Cert       *dnscert.Service
	Automation *dnsautomation.Service
	Optimize   *dnsoptimize.Service
}
type service struct {
	deploy     DeploymentFunc
	cert       *dnscert.Service
	resolve    resolver
	automation *dnsautomation.Service
	optimize   *dnsoptimize.Service
}

func Bind(root *router.RouterGroup[*core.RequestEvent], resolve resolver, dependencies Services) {
	s := service{deploy: dependencies.Deploy, cert: dependencies.Cert, resolve: resolve, automation: dependencies.Automation, optimize: dependencies.Optimize}
	keys := root.Group("/api/dns-keys")
	keys.Bind(apis.RequireAuth(core.CollectionNameSuperusers, dnsauth.Members), apis.BodyLimit(bodyLimit))
	keys.GET("", listKeys)
	keys.GET("/actions", func(e *core.RequestEvent) error {
		if !apiEnabled(e.Auth) {
			return e.ForbiddenError("Interface access disabled", nil)
		}
		return e.JSON(200, actionsForActor(e.Auth))
	})
	keys.POST("", issueKey)
	keys.DELETE("/{uid}", revokeKey)
	// GET also has an explicit route so the SPA catch-all never serves HTML
	// to an MCP client negotiating a stream.
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
		root.Route(method, "/mcp", s.mcp).Bind(authorize("mcp"), apis.BodyLimit(bodyLimit))
	}
	api := root.Group("/api")
	api.Bind(authorize("api"), apis.BodyLimit(bodyLimit))
	api.POST("/cert/order", s.rest("cert_order_query", "get"))
	api.POST("/domain", s.rest("domain_query", "list"))
	api.POST("/domain/{id}", s.rest("domain_query", "info"))
	api.POST("/record/data/{id}", s.rest("record_query", "list"))
	for _, op := range []struct{ path, action string }{
		{"add", "add"}, {"update", "update"}, {"delete", "delete"}, {"status", "set_status"}, {"remark", "set_remark"}, {"batch", "batch"},
	} {
		api.POST("/record/"+op.path+"/{id}", s.rest("record_manage", op.action))
	}
}

func (s service) rest(tool, action string) func(*core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		args := object{}
		for k, v := range e.Request.PostForm {
			if k != "uid" && k != "sign" && k != "timestamp" {
				args[k] = v[0]
			}
		}
		if id := e.Request.PathValue("id"); id != "" {
			key := "domain_id"
			if tool == "domain_query" {
				key = "id"
			}
			args[key] = localZoneID(e, id)
		}
		if action == "batch" {
			args["batch_action"] = args["action"]
			args["records"] = args["recordinfo"]
		}
		args["action"] = action
		out, err := s.execute(e, tool, args)
		if err != nil {
			return e.JSON(err.status, failure(err.message))
		}
		if tool == "domain_query" {
			if err := legacyDomains(e, out); err != nil {
				return e.JSON(500, failure("Could not read numeric domain identity"))
			}
		}
		return e.JSON(200, out)
	}
}

func failure(msg string) object { return object{"code": -1, "msg": msg} }

func validOrigin(e *core.RequestEvent) bool {
	values := e.Request.Header.Values("Origin")
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	u, err := url.Parse(values[0])
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Host == "" || !strings.EqualFold(u.Host, e.Request.Host) {
		return false
	}
	scheme := "http"
	if e.Request.TLS != nil {
		scheme = "https"
	}
	if scheme == u.Scheme {
		return true
	}
	// TLS can terminate at a reverse proxy. Match only the configured public origin.
	public, err := url.Parse(e.App.Settings().Meta.AppURL)
	return e.Request.TLS == nil && u.Scheme == "https" && err == nil && public.Scheme == u.Scheme && strings.EqualFold(public.Host, u.Host)
}

func (s service) mcp(e *core.RequestEvent) error {
	if !validOrigin(e) {
		return e.JSON(403, rpcError(nil, -32000, "Origin not allowed"))
	}
	if e.Request.Method != http.MethodPost {
		e.Response.Header().Set("Allow", "POST")
		return e.JSON(405, rpcError(nil, -32000, "Method not allowed"))
	}
	body, err := io.ReadAll(e.Request.Body)
	if err != nil {
		return e.JSON(413, rpcError(nil, -32600, "Request body too large"))
	}
	if !json.Valid(body) {
		return e.JSON(200, rpcError(nil, -32700, "Parse error"))
	}
	var payload json.RawMessage
	_ = json.Unmarshal(body, &payload)
	if payload[0] == '[' {
		var batch []json.RawMessage
		_ = json.Unmarshal(payload, &batch)
		if len(batch) == 0 || len(batch) > 32 {
			return e.JSON(200, rpcError(nil, -32600, "Invalid batch size"))
		}
		results := []object{}
		for _, raw := range batch {
			if out := s.dispatch(e, raw); out != nil {
				results = append(results, out)
			}
		}
		if len(results) > 0 {
			return e.JSON(200, results)
		}
	} else if out := s.dispatch(e, payload); out != nil {
		return e.JSON(200, out)
	}
	return e.NoContent(202)
}

func rpcError(id json.RawMessage, code int, msg string) object {
	return object{"jsonrpc": "2.0", "id": id, "error": object{"code": code, "message": msg}}
}

func (s service) dispatch(e *core.RequestEvent, raw json.RawMessage) object {
	var msg struct {
		Version string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  struct {
			Protocol  string `json:"protocolVersion"`
			Name      string `json:"name"`
			Arguments object `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil || msg.Version != "2.0" || msg.Method == "" {
		return rpcError(nil, -32600, "Invalid Request")
	}
	if len(msg.ID) == 0 {
		return nil
	} // Notifications are acknowledged without performing tool operations.
	if !slices.Contains([]byte{'"', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'n'}, msg.ID[0]) {
		return rpcError(nil, -32600, "Invalid request ID")
	}
	var result any
	switch msg.Method {
	case "initialize":
		version := msg.Params.Protocol
		if !slices.Contains([]string{"2025-06-18", "2025-03-26", "2024-11-05"}, version) {
			version = "2025-06-18"
		}
		result = object{"protocolVersion": version, "capabilities": object{"tools": object{"listChanged": false}}, "serverInfo": object{"name": "certimate-dns", "version": "1"}, "instructions": "Use domain_query(list) to discover authorized local domain IDs."}
	case "ping":
		result = object{}
	case "tools/list":
		grant, _ := e.Get(scopeKey).(scope)
		result = object{"tools": toolSchemas(grant, e.Auth)}
	case "tools/call":
		if !slices.ContainsFunc(tools, func(t toolDefinition) bool { return t.name == msg.Params.Name }) {
			return rpcError(msg.ID, -32602, "Unknown tool")
		}
		data, err := s.execute(e, msg.Params.Name, msg.Params.Arguments)
		if err != nil {
			data = failure(err.message)
		}
		encoded, _ := json.Marshal(data)
		result = object{"structuredContent": data, "content": []object{{"type": "text", "text": string(encoded)}}, "isError": err != nil}
	default:
		return rpcError(msg.ID, -32601, "Method not found")
	}
	return object{"jsonrpc": "2.0", "id": msg.ID, "result": result}
}
