package dnsmcp

import (
	_ "embed"
	"encoding/json"
	"github.com/pocketbase/pocketbase/core"
	"maps"
	"slices"
	"strings"
)

type operation struct{ name, permission string }
type toolDefinition struct {
	name, description string
	methods           []operation
	fields            []string
}

var baseTools = []toolDefinition{
	{"domain_query", "List and inspect authorized DNS domains.", []operation{{"list", "domain.read"}, {"get", "domain.read"}, {"info", "domain.read"}, {"quickinfo", "domain.read"}}, []string{"id", "kw", "aid", "type", "offset", "limit"}},
	{"record_query", "Read DNS records, provider groups and change history.", []operation{{"list", "record.read"}, {"subdomain", "record.read"}, {"groups", "record.read"}, {"log", "record.read"}}, []string{"domain_id", "keyword", "subdomain", "rr", "value", "type", "line", "status", "offset", "limit"}},
	{"record_manage", "Change records within a granted domain. DNS record IDs come from record_query.", []operation{{"add", "record.add"}, {"update", "record.update"}, {"delete", "record.delete"}, {"set_status", "record.status"}, {"set_remark", "record.remark"}, {"batch", "record.batch"}}, []string{"domain_id", "recordid", "name", "type", "value", "ttl", "line", "status", "remark", "records", "batch_action", "groupid"}},
}

// schema.json contains the pinned DNSMgr MCP parameter definitions (see schema.LICENSE).
// Resource IDs additionally accept the native Certimate string representation.
//
//go:embed schema.json
var schemaJSON []byte

type signature struct {
	Title         string
	Properties    map[string]any
	Required      []string
	MemberActions []string
	Actions       []string
	ReadOnly      bool
	Destructive   bool
}

var signatures = func() map[string]signature {
	var result map[string]signature
	if err := json.Unmarshal(schemaJSON, &result); err != nil {
		panic(err)
	}
	return result
}()
var tools = func() []toolDefinition {
	all := slices.Clone(baseTools)
	all[0].methods = append(all[0].methods, extendedDomainOps...)
	all[1].methods = append(all[1].methods, extendedRecordQueryOps...)
	all[2].methods = append(all[2].methods, extendedRecordManageOps...)
	return slices.Concat(all, domainTools, certTools, cfTools, taskTools)
}()

func actionsForActor(actor *core.Record) []string {
	var result []string
	for _, t := range tools {
		for _, op := range t.methods {
			if !roleAllows(actor, t.name, op.name) || slices.Contains(result, op.permission) {
				continue
			}
			result = append(result, op.permission)
		}
	}
	return append(result, "record.group", "domain.login")
}

func roleAllows(actor *core.Record, tool, action string) bool {
	sig, ok := signatures[tool]
	return ok && actorAllowed(actor) && slices.Contains(sig.Actions, action) && (actor.IsSuperuser() || slices.Contains(sig.MemberActions, action))
}

func isWrite(permission string) bool {
	return !strings.HasSuffix(permission, ".read") && permission != "domain.login"
}

func isZoneWrite(permission string) bool {
	if !isWrite(permission) {
		return false
	}
	return strings.HasPrefix(permission, "record.") || strings.HasPrefix(permission, "domain.") || strings.HasPrefix(permission, "cf.hostname.")
}

func toolSchemas(grant scope, actor *core.Record) []object {
	out := []object{}
	for _, tool := range tools {
		sig := signatures[tool.name]
		permitted := []string{}
		for _, op := range tool.methods {
			if roleAllows(actor, tool.name, op.name) && slices.Contains(grant.Actions, op.permission) {
				permitted = append(permitted, op.name)
			}
		}
		if len(permitted) == 0 {
			continue
		}
		// Every returned schema is independent of the shared signatures and other keys.
		properties := maps.Clone(sig.Properties)
		if properties == nil {
			properties = object{}
		}
		required := slices.Clone(sig.Required)
		if len(sig.Actions) > 1 {
			properties["action"] = object{"type": "string", "enum": permitted}
			required = append([]string{"action"}, required...)
		}
		for _, field := range tool.fields {
			if _, ok := properties[field]; ok {
				continue
			}
			kind := "string"
			switch field {
			case "version", "page", "renewal_version", "interval":
				kind = "integer"
			case "request", "versions":
				kind = "object"
			case "confirm_quota", "preview":
				kind = "boolean"
			}
			properties[field] = object{"type": kind}
		}
		schema := object{"type": "object", "properties": properties}
		if len(required) > 0 {
			schema["required"] = required
		}
		out = append(out, object{"name": tool.name, "title": sig.Title, "description": tool.description, "inputSchema": schema, "annotations": object{"title": sig.Title, "readOnlyHint": sig.ReadOnly, "destructiveHint": sig.Destructive, "openWorldHint": true}})
	}
	return out
}
