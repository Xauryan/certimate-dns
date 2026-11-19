package dnsmcp_test

import (
	"strings"
	"testing"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

// Exercise filtering through the normal JSON-RPC entry point. The three excluded
// entries distinguish zone, owner collection and message projection constraints.
func TestDomainAuditProjectionAndOverview(t *testing.T) {
	f := setupInterface(t)
	key := f.issue(t, session(t, f.member), f.keyInput([]string{"operationlog.read", "overview.read"}, []string{"mcp"}))
	call := func(tool string, args fields) fields {
		t.Helper()
		w := f.request("POST", "/mcp", key.bearer(), "application/json", testJSON(t, fields{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": fields{"name": tool, "arguments": args}}))
		expectStatus(t, w, 200)
		if strings.Contains(w.Body.String(), configSentinel) || strings.Contains(w.Body.String(), "hidden.example") {
			t.Fatal("disclosed out-of-scope data")
		}
		var result struct {
			Result struct {
				Data   fields `json:"structuredContent"`
				Failed bool   `json:"isError"`
			}
		}
		readJSON(t, w, &result)
		if result.Result.Failed || result.Result.Data == nil {
			t.Fatal("tool execution failed")
		}
		return result.Result.Data
	}
	insert := func(message, collection, zone string) {
		t.Helper()
		_, err := f.app.AuxDB().Insert(core.LogsTableName, dbx.Params{"message": message, "data": testJSON(t, fields{"actor": f.member.Id, "actorCollection": collection, "zone": zone, "action": "update", "success": true, "payload": configSentinel})}).Execute()
		if err != nil {
			t.Fatal(err)
		}
	}
	insert("DNS interface record operation", f.member.Collection().Name, f.visible.Id)
	insert("DNS interface record operation", f.member.Collection().Name, f.hidden.Id)
	insert("DNS interface record operation", core.CollectionNameSuperusers, f.visible.Id)
	insert("unscoped message", f.member.Collection().Name, f.visible.Id)
	rows := call("operation_log_query", fields{"action": "list", "kw": "update", "limit": 1})
	if rows["total"] != float64(1) || len(rows["rows"].([]any)) != 1 {
		t.Fatal("incorrect audit count")
	}
	if page := call("operation_log_query", fields{"action": "list", "offset": 1}); page["total"] != float64(1) || len(page["rows"].([]any)) != 0 {
		t.Fatal("incorrect scoped audit page")
	}
	stats := call("get_overview", fields{"action": "stat"})
	if stats["domains"] != float64(1) {
		t.Fatal("out-of-scope domain counted")
	}
}
