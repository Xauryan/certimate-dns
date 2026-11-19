package dnsmcp

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/dnsbatch"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type opError struct {
	status  int
	message string
}

var (
	denied      = &opError{403, "Operation outside credential scope"}
	missing     = &opError{404, "Domain or record unavailable"}
	invalid     = &opError{400, "Invalid operation parameters"}
	unsupported = &opError{422, "Unsupported provider capability or change"}
	upstream    = &opError{502, "Provider request failed; refresh records before retrying a change"}
)

func str(args object, k string) string {
	switch v := args[k].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		return v.String()
	default:
		return ""
	}
}

func number(args object, k string, def, min, max int) (int, bool) {
	if _, found := args[k]; !found {
		return def, true
	}
	n, err := strconv.Atoi(str(args, k))
	return n, err == nil && n >= min && n <= max
}

func paging(args object) (int, int, bool) {
	offset, ok := number(args, "offset", 0, 0, 10000000)
	limit, ok2 := number(args, "limit", 20, 1, 100)
	return offset, limit, ok && ok2
}

func page[T any](rows []T, offset, limit int) object {
	return object{"total": len(rows), "rows": rows[min(offset, len(rows)):min(offset+limit, len(rows))]}
}

func providerType(name string) string {
	return legacyAccountType(name)
}

func zoneInfo(z dnsauth.Zone) object {
	return object{"id": z.ID, "name": z.Name, "aid": z.AccessID, "type": legacyAccountType(z.Provider), "thirdid": z.ZoneID, "status": z.Status}
}

func (s service) execute(e *core.RequestEvent, tool string, args object) (object, *opError) {
	action := str(args, "action")
	var permission string
	for _, t := range tools {
		if t.name == tool {
			if action == "" && len(t.methods) == 1 {
				action = t.methods[0].name
			}
			for _, op := range t.methods {
				if op.name == action {
					permission = op.permission
					break
				}
			}
		}
	}
	if permission == "" {
		return nil, invalid
	}
	grant, ok := e.Get(scopeKey).(scope)
	if !ok || !roleAllows(e.Auth, tool, action) || !slices.Contains(grant.Actions, permission) || !activeGrant(e) {
		return nil, denied
	}
	switch {
	case strings.HasPrefix(tool, "cert_"):
		return s.executeCert(e, tool, action, args, grant)
	case strings.HasPrefix(tool, "cf_"):
		return s.executeCF(e, tool, action, args, grant)
	case strings.HasPrefix(tool, "dmonitor_"), strings.HasPrefix(tool, "optimizeip_"), strings.HasPrefix(tool, "schedule_"):
		return s.executeTask(e, tool, action, args, grant)
	case tool == "domain_query" && action == "list":
		return domains(e, grant, args)
	case tool == "domain_query" && slices.Contains([]string{"get", "info", "quickinfo"}, action):
	case tool == "record_manage", tool == "record_query":
	default:
		return s.executeDomain(e, tool, action, args, grant)
	}
	key := "domain_id"
	if tool == "domain_query" {
		key = "id"
	}
	id := str(args, key)
	if id == "" {
		return nil, invalid
	}
	if !slices.Contains(grant.Zones, id) {
		return nil, missing
	}
	z, err := dnsauth.GetZone(e, id, isWrite(permission))
	if err != nil {
		return nil, missing
	}
	var data object
	if tool == "domain_query" {
		var problem *opError
		data, problem = domainDetailRow(e, z)
		if problem != nil {
			return nil, problem
		}
		if action == "get" {
			return object{"code": 0, "data": data}, nil
		}
	}
	p, err := s.resolve(e.Request.Context(), z.Provider, z.AccessID, false)
	if err != nil || p == nil {
		return nil, upstream
	}
	if tool == "domain_query" {
		lines := []dns.RecordLine{}
		ttl := 1
		if details, ok := p.(interface {
			ZoneDetails(context.Context, string) (*dns.ZoneDetails, error)
		}); ok {
			info, err := details.ZoneDetails(e.Request.Context(), z.ZoneID)
			if err != nil || info == nil {
				return nil, upstream
			}
			if len(info.Lines) > 0 {
				lines = info.Lines
			}
			ttl = max(ttl, info.MinTTL)
		}
		fields := []string{}
		if meta, ok := p.(dnsbatch.Metadata); ok {
			fields = meta.BatchFields()
		}
		alias := slices.Contains([]string{"powerdns", "henet", "spaceship"}, z.Provider)
		caps := object{"type": legacyAccountType(z.Provider), "weight": slices.Contains(fields, "weight"), "remark": slices.Contains(fields, "remark"), "alias": alias, "attributes": fields}
		if action == "quickinfo" {
			data = caps
		} else {
			data["config"] = caps
		}
		data["recordLine"] = lines
		data["minTTL"] = ttl
		if action == "info" && str(args, "loginurl") == "1" {
			if !slices.Contains(grant.Actions, "domain.login") || !slices.Contains(grant.Actions, "record.read") {
				return nil, denied
			}
			uid, _ := e.Get(keyUID).(string)
			link, err := dnsauth.IssueQuickLink(e, z.ID, false, uid)
			if err != nil {
				return nil, denied
			}
			data["loginurl"] = strings.TrimRight(e.App.Settings().Meta.AppURL, "/") + "/" + strings.TrimLeft(link, "/")
		}
		return object{"code": 0, "data": data}, nil
	}
	if tool == "record_query" {
		out, problem := query(e, p, z, action, args)
		if problem == nil && action == "list" && args["keyword"] == nil && args["subdomain"] == nil && args["value"] == nil && args["type"] == nil && args["line"] == nil && args["status"] == nil {
			if total, ok := out["total"].(int); ok {
				_, _ = e.App.DB().NewQuery(`INSERT INTO dns_interface_zones (zone,recordcount) VALUES ({:zone},{:records}) ON CONFLICT(zone) DO UPDATE SET recordcount=excluded.recordcount`).Bind(dbx.Params{"zone": z.ID, "records": total}).WithContext(e.Request.Context()).Execute()
			}
		}
		return out, problem
	}
	data, opErr := mutate(e, p, z, grant, action, args)
	e.App.Logger().Info("DNS interface record operation", "actorCollection", e.Auth.Collection().Name, "actor", e.Auth.Id, "zone", z.ID, "action", action, "success", opErr == nil && data["code"] == 0)
	return data, opErr
}

func domains(e *core.RequestEvent, grant scope, args object) (object, *opError) {
	offset, limit, ok := paging(args)
	if !ok {
		return nil, invalid
	}
	rows := []object{}
	for _, id := range grant.Zones {
		z, err := dnsauth.GetZone(e, id, false)
		if errors.Is(err, domain.ErrRecordNotFound) {
			continue
		}
		if err != nil {
			return nil, &opError{500, "Could not list authorized domains"}
		}
		r, visible, problem := domainListRow(e, z, args)
		if problem != nil {
			return nil, problem
		}
		if visible {
			var count int
			err = e.App.DB().NewQuery(`SELECT COALESCE((SELECT recordcount FROM dns_interface_zones WHERE zone={:zone}),0)`).Bind(dbx.Params{"zone": id}).Row(&count)
			if err != nil {
				return nil, upstream
			}
			r["recordcount"] = count
			rows = append(rows, r)
		}
	}
	field := str(args, "sortName")
	if !slices.Contains([]string{"id", "name", "recordcount", "regtime", "expiretime", "is_notice", "is_hide", "is_sso", "typename", "category_name", "remark"}, field) {
		field = "id"
	}
	ascending := strings.EqualFold(str(args, "sortOrder"), "asc")
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		var comparison int
		if av, ok := a[field].(int); ok {
			bv, _ := b[field].(int)
			comparison = cmp.Compare(av, bv)
		} else {
			comparison = strings.Compare(str(a, field), str(b, field))
		}
		if comparison == 0 {
			comparison = strings.Compare(str(a, "id"), str(b, "id"))
		}
		if ascending {
			return comparison < 0
		}
		return comparison > 0
	})
	return page(rows, offset, limit), nil
}
