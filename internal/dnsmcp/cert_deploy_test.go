package dnsmcp

import (
	"net/http/httptest"
	"testing"

	_ "github.com/certimate-go/certimate/migrations"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

func TestCertDeployScopeClaimAndAtomicBatch(t *testing.T) {
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.ResetBootstrapState() })
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	save := func(table string, fields object) *core.Record {
		t.Helper()
		c, err := app.FindCollectionByNameOrId(table)
		if err != nil {
			t.Fatal(err)
		}
		r := core.NewRecord(c)
		for k, v := range fields {
			r.Set(k, v)
		}
		if err = app.Save(r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	ca := save("access", object{"name": "issuer", "provider": "aliyun", "config": object{}})
	dest := save("access", object{"name": "deploy", "provider": "aliyun", "config": object{}})
	save("dnsAccount", object{"id": ca.Id, "accessRef": ca.Id})
	zone := save("dnsZone", object{"accountRef": ca.Id, "providerZoneId": "zone-1", "name": "example.test", "present": true})
	_, err := app.DB().Insert("dns_cert_orders", dbx.Params{"id": "certificateorder1", "access_id": ca.Id, "provider": "aliyun", "domain": "www.example.test", "primary_zone_id": zone.Id, "algorithm": "RSA2048", "request_json": "{}", "state": "draft", "created": 1, "updated": 1}).Execute()
	if err != nil {
		t.Fatal(err)
	}
	node := object{"id": "approved", "type": "bizDeploy", "data": object{"config": object{"provider": "aliyun-cdn", "providerAccessId": dest.Id, "providerConfig": object{"domain": "www.example.test"}}}}
	w := save("workflow", object{"name": "Published TLS deployment", "trigger": "manual", "enabled": true, "hasContent": true, "graphContent": object{"nodes": []object{{"id": "start", "type": "start"}, node, {"id": "end", "type": "end"}}}})
	super, err := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		t.Fatal(err)
	}
	e := &core.RequestEvent{App: app, Auth: core.NewRecord(super)}
	e.Request = httptest.NewRequest("POST", "/mcp", nil)
	g := scope{Global: true, Zones: []string{zone.Id}, Accounts: []string{ca.Id, dest.Id}, Actions: []string{"cert.deploy.active"}}
	in := object{"oid": "certificateorder1", "aid": dest.Id, "config": object{"workflowId": w.Id, "nodeId": "approved"}}
	s := service{}
	result, problem := s.certDeploy(e, "cert_deploy_manage", "add", in, g)
	if problem != nil {
		t.Fatal(problem)
	}
	id := result["id"].(string)
	if _, problem = s.certDeploy(e, "cert_deploy_manage", "edit", object{"id": id, "config": object{"filePathForKey": "/tmp/unsupported"}}, g); problem != invalid {
		t.Fatalf("unexpected direct config outcome %v", problem)
	}
	for _, limited := range []scope{{Global: true, Accounts: g.Accounts}, {Global: true, Zones: g.Zones, Accounts: []string{ca.Id}}, {Global: true, Zones: g.Zones, Accounts: []string{dest.Id}}} {
		result, problem = s.certDeploy(e, "cert_deploy_query", "list", object{}, limited)
		if problem != nil || result["total"] != 0 {
			t.Fatalf("scope leaked task: %v (%v)", result, problem)
		}
		if _, problem = s.certDeploy(e, "cert_deploy_manage", "del", object{"id": id}, limited); problem != missing {
			t.Fatal("cross-scope deletion", problem)
		}
	}
	result, problem = s.certDeploy(e, "cert_deploy_query", "list", object{"limit": "1"}, g)
	if problem != nil || result["total"] != 1 {
		t.Fatalf("task missing: %v (%v)", result, problem)
	}
	_, problem = s.certDeploy(e, "cert_deploy_manage", "batch", object{"ids": []any{id, "missing"}, "act": "close"}, g)
	if problem != missing {
		t.Fatal("expected batch failure", problem)
	}
	row, problem := deployTaskRow(app, "id", id)
	if problem != nil || !row.Active || row.Version != 1 {
		t.Fatal("batch not rolled back", row, problem)
	}
	// Two concurrent process intents initially see the same version. Exactly one
	// claims the task. A reset cannot clear a live transfer.
	now := int64(4102444800)
	values := func() dbx.Params { return dbx.Params{"process_id": "test-process", "started": now} }
	if problem = deployCAS(app, row, values(), false); problem != nil {
		t.Fatal(problem)
	}
	if problem = deployCAS(app, row, values(), false); problem != deployConflict {
		t.Fatal("duplicate lease", problem)
	}
	if _, problem = s.certDeploy(e, "cert_deploy_manage", "reset", object{"id": id}, g); problem != deployConflict {
		t.Fatal("reset in-flight", problem)
	}
	result, problem = s.certDeploy(e, "cert_deploy_query", "show_log", object{"processid": "test-process"}, g)
	if problem != nil || result["data"] != "Deployment started" {
		t.Fatal("missing process history", result, problem)
	}
	w.Set("enabled", false)
	if err = app.Save(w); err != nil {
		t.Fatal(err)
	}
	if _, _, problem = deployDestination(app, row); problem != missing {
		t.Fatal("disabled destination", problem)
	}
}
