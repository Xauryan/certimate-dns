package dnsmcp

import (
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/pocketbase/pocketbase/core"
)

func taskTool(name, description string, methods, fields []string) toolDefinition {
	var ops []operation
	prefix := strings.Split(name, "_")[0]
	for _, m := range methods {
		permission := prefix + "." + m
		if strings.HasSuffix(name, "_query") {
			permission = prefix + ".read"
		}
		if m == "api_balance" {
			permission = "optimizeip.balance.read"
		}
		ops = append(ops, operation{m, permission})
	}
	return toolDefinition{name, description, ops, fields}
}

var taskTools = []toolDefinition{
	taskTool("dmonitor_query", "Inspect failover policies and switch events in granted zones.", []string{"overview", "list", "info", "logs"}, strings.Fields("id kw type status log_action offset limit sortName sortOrder")),
	taskTool("dmonitor_manage", "Maintain failover tasks. New tasks start as drafts.", []string{"add", "edit", "set_active", "del", "batch", "clean_logs"}, strings.Fields("id ids did rr recordid recordinfo main_value type backup_value checktype checkurl tcpport frequency cycle timeout proxy cdn remark active act days")),
	taskTool("optimizeip_query", "List ranked-address tasks or query a feed balance.", []string{"list", "api_balance"}, strings.Fields("kw type status offset limit sortName sortOrder source")),
	taskTool("optimizeip_manage", "Manage grouped carrier-line address tasks. For run or enabling, submit preview=true, then repeat with the returned digest.", []string{"add", "edit", "set_active", "del", "run"}, strings.Fields("id did rr type cdn_type ip_type recordnum ttl remark active source interval preview digest")),
	taskTool("schedule_query", "List scheduled DNS changes in granted zones.", []string{"list"}, strings.Fields("kw type stype offset limit sortName sortOrder")),
	taskTool("schedule_manage", "Maintain scheduled DNS changes. New schedules start as drafts. Local dates default to Asia/Shanghai.", []string{"add", "edit", "set_active", "del", "batch"}, strings.Fields("id ids did rr recordid recordinfo type cycle switchdate switchtime switchtype value line remark active act timezone")),
}

func (s service) executeTask(e *core.RequestEvent, tool, action string, args object, grant scope) (object, *opError) {
	if !e.HasSuperuserAuth() {
		return nil, denied
	}
	write := strings.HasSuffix(tool, "_manage")
	zones := make([]dnsauth.Zone, 0, len(grant.Zones))
	for _, id := range grant.Zones {
		z, err := dnsauth.GetZone(e, id, write)
		if errors.Is(err, domain.ErrRecordNotFound) {
			continue
		}
		if err != nil {
			return nil, denied
		}
		zones = append(zones, z)
	}
	if strings.HasPrefix(tool, "optimizeip_") {
		return s.optimizeTool(e, action, args, zones)
	}
	if s.automation == nil {
		return nil, unsupported
	}
	kind := "schedule"
	if strings.HasPrefix(tool, "dmonitor_") {
		kind = "failover"
	}
	return s.automationTool(e, kind, action, args, zones, grant)
}

func findTaskZone(zones []dnsauth.Zone, id string) (dnsauth.Zone, bool) {
	for _, z := range zones {
		if z.ID == id {
			return z, true
		}
	}
	return dnsauth.Zone{}, false
}

func taskBool(args object, field string) (bool, bool) {
	switch x := args[field].(type) {
	case bool:
		return x, true
	default:
		switch str(args, field) {
		case "1", "true":
			return true, true
		case "0", "false":
			return false, true
		}
	}
	return false, false
}
func taskString(args object, key, def string) string {
	if _, ok := args[key]; ok {
		return str(args, key)
	}
	return def
}
func taskSuccess(id string) object { return object{"code": 0, "msg": "OK", "id": id} }
func taskIDs(input any) ([]string, bool) {
	data, err := json.Marshal(input)
	if err != nil {
		return nil, false
	}
	var vals []any
	if json.Unmarshal(data, &vals) != nil || len(vals) == 0 || len(vals) > 100 {
		return nil, false
	}
	ids := make([]string, 0, len(vals))
	for _, v := range vals {
		id := str(object{"id": v}, "id")
		if id == "" || slices.Contains(ids, id) {
			return nil, false
		}
		ids = append(ids, id)
	}
	return ids, true
}
func taskPage(rows []object, args object, sortable ...string) (object, *opError) {
	offset, limit, ok := paging(args)
	if !ok {
		return nil, invalid
	}
	key := taskString(args, "sortName", "id")
	if !slices.Contains(sortable, key) {
		return nil, invalid
	}
	order := taskString(args, "sortOrder", "desc")
	if order != "asc" && order != "desc" {
		return nil, invalid
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if order == "desc" {
			a, b = b, a
		}
		switch x := a[key].(type) {
		case int:
			y, _ := b[key].(int)
			if x != y {
				return x < y
			}
		case int64:
			y, _ := b[key].(int64)
			if x != y {
				return x < y
			}
		default:
			left, right := str(a, key), str(b, key)
			if left != right {
				return left < right
			}
		}
		return str(a, "id") < str(b, "id")
	})
	return page(rows, offset, limit), nil
}
func containsTaskFilter(row object, args object, fields []string) bool {
	kw := strings.ToLower(str(args, "kw"))
	if kw == "" {
		return true
	}
	index, ok := number(args, "type", 1, 1, len(fields))
	if !ok {
		return false
	}
	field := fields[index-1]
	return strings.Contains(strings.ToLower(str(row, field)), kw) || field == "rr" && strings.Contains(strings.ToLower(str(row, "domain")), kw)
}
func taskInt(v any) string {
	switch x := v.(type) {
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	default:
		return str(object{"v": v}, "v")
	}
}
