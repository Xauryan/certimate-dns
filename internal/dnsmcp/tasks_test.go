package dnsmcp

import (
	"encoding/json"
	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/dnsautomation"
	"github.com/certimate-go/certimate/internal/dnsoptimize"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"net/http/httptest"
	"testing"
)

func taskTestApp(t *testing.T) (*core.BaseApp, *core.RequestEvent) {
	t.Helper()
	a := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := a.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.ResetBootstrapState() })
	if err := dnsautomation.Install(a); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"CREATE TABLE dns_monitor_log_cutoffs(task TEXT PRIMARY KEY,cutoff INTEGER NOT NULL)", "CREATE TABLE dns_optimize_groups(id TEXT PRIMARY KEY,zone TEXT,config TEXT,children TEXT)", "CREATE TABLE dns_optimize_tasks(id TEXT PRIMARY KEY,provider TEXT,access TEXT,zone TEXT,config TEXT,enabled INTEGER,status TEXT,last_run INTEGER,interval INTEGER)"} {
		if _, err := a.DB().NewQuery(q).Execute(); err != nil {
			t.Fatal(err)
		}
	}
	e := &core.RequestEvent{}
	e.App = a
	e.Request = httptest.NewRequest("POST", "/mcp", nil)
	c, err := a.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		t.Fatal(err)
	}
	e.Auth = core.NewRecord(c)
	e.Auth.Id = "actor"
	return a, e
}

func TestTaskScopedQueriesAndHistory(t *testing.T) {
	a, e := taskTestApp(t)
	s := service{automation: dnsautomation.New(a, nil, nil)}
	visible := dnsauth.Zone{ID: "one", AccessID: "account1", ZoneID: "upstream-id", Name: "one.example"}
	hidden := dnsauth.Zone{ID: "two", AccessID: "account2", ZoneID: "upstream-id", Name: "two.example"}
	zones := []dnsauth.Zone{visible}
	def := func(z dnsauth.Zone) dnsautomation.Definition {
		return dnsautomation.Definition{Name: "monitor", Kind: "failover", Action: "standby", Target: dnsautomation.Target{AccountID: z.AccessID, ZoneID: z.ZoneID, Name: z.Name, RecordID: "r", Type: "A"}, Monitor: dnsautomation.Monitor{Interval: 60, FailureThreshold: 1, RecoveryThreshold: 1}}
	}
	for _, z := range []dnsauth.Zone{visible, hidden} {
		if _, err := s.automation.CreateDraftWithID(e.Request.Context(), z.ID, "actor", def(z)); err != nil {
			t.Fatal(err)
		}
	}
	got, prob := s.automationTool(e, "failover", "list", object{}, zones, scope{})
	if prob != nil || got["total"] != 1 {
		t.Fatalf("scoped list %v %v", got, prob)
	}
	rows := got["rows"].([]object)
	if rows[0]["did"] != visible.ID {
		t.Fatal(rows)
	}
	if _, prob = s.automationTool(e, "failover", "info", object{"id": hidden.ID}, zones, scope{}); prob != missing {
		t.Fatalf("ungranted task detail: %v", prob)
	}
	if _, prob = s.automationTool(e, "failover", "batch", object{"ids": []string{visible.ID, hidden.ID}, "act": "delete"}, zones, scope{Actions: []string{"dmonitor.del"}}); prob != missing {
		t.Fatalf("ungranted task in batch %v", prob)
	}
	for _, z := range []dnsauth.Zone{visible, hidden} {
		_, err := a.DB().NewQuery("INSERT INTO dns_automation_runs(id,task_id,actor,action,outcome,started,finished,before_record,after_record) VALUES({:id},{:task},'scheduler','enable','verified',1,2,'{}','{}')").Bind(dbx.Params{"id": "r" + z.ID, "task": z.ID}).Execute()
		if err != nil {
			t.Fatal(err)
		}
	}
	logArgs := object{"id": "one"}
	got, prob = s.automationTool(e, "failover", "logs", logArgs, zones, scope{})
	if prob != nil || got["total"] != 1 {
		t.Fatalf("logs %v %v", got, prob)
	}
	_, prob = s.automationTool(e, "failover", "clean_logs", object{"days": "1"}, zones, scope{})
	if prob != nil {
		t.Fatal(prob)
	}
	got, prob = s.automationTool(e, "failover", "logs", logArgs, zones, scope{})
	if prob != nil || got["total"] != 0 {
		t.Fatalf("cleaned logs %v %v", got, prob)
	}
	var retained int
	if err := a.DB().NewQuery("SELECT count(*) FROM dns_automation_runs WHERE outcome='verified'").Row(&retained); err != nil || retained != 2 {
		t.Fatal(retained, err)
	}
}

func TestTaskLegacyMappings(t *testing.T) {
	z := dnsauth.Zone{ID: "zone", Name: "example.test", AccessID: "account", ZoneID: "provider-id"}
	a := object{"rr": "www", "recordid": "r1", "recordinfo": object{"Value": "8.8.8.8"}, "switchtime": "2030-11-21T08:25", "value": "1.1.1.1"}
	d, err := automationDefinition(a, "schedule", z, nil)
	if err != nil || d.Target.Name != "www.example.test" || d.Target.AccountID != "account" || d.Schedule.At != "2030-11-21T08:25:00+08:00" {
		t.Fatalf("%#v %v", d, err)
	}
	a["rr"] = "bad.example.org."
	if _, err = automationDefinition(a, "schedule", z, nil); err == nil {
		t.Fatal("accepted absolute name outside zone")
	}
	_, specs, err := optimizationConfig(object{"rr": "@", "type": "1", "ip_type": "v4,v6", "source": "wetest"}, z)
	if err != nil || len(specs) != 6 || specs[0].TargetLine != "DEF" || specs[0].SourceLine != "CT" || specs[3].Family != "v6" {
		t.Fatalf("group %v %v", specs, err)
	}
}

func TestTaskOptimizeGroupsScopedBeforePaging(t *testing.T) {
	a, e := taskTestApp(t)
	s := service{optimize: dnsoptimize.New(a, nil)}
	z := dnsauth.Zone{ID: "one", AccessID: "access", ZoneID: "up", Provider: "aliyun", Name: "example.test"}
	cfg, _, prob := optimizationConfig(object{"rr": "www"}, z)
	if prob != nil {
		t.Fatal(prob)
	}
	raw, _ := json.Marshal(cfg)
	for _, id := range []string{"one", "outside"} {
		_, err := a.DB().NewQuery("INSERT INTO dns_optimize_groups VALUES({:id},{:zone},{:config},'[\"line\"]')").Bind(dbx.Params{"id": "g" + id, "zone": id, "config": string(raw)}).Execute()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err := a.DB().NewQuery("INSERT INTO dns_optimize_tasks VALUES('line','aliyun','access','up','{}',1,'success',1000,60)").Execute()
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.DB().NewQuery(`INSERT INTO dns_optimize_tasks VALUES('single','aliyun','access','up','{"name":"b.example.test","cdn":"cloudflare","family":"v4","sourceLine":"CT","targetLine":"CT","ranks":[3]}',0,'',0,60)`).Execute()
	if err != nil {
		t.Fatal(err)
	}
	got, prob := s.optimizeTool(e, "list", object{}, []dnsauth.Zone{z})
	if prob != nil || got["total"] != 2 || got["rows"].([]object)[0]["id"] != "single" || got["rows"].([]object)[1]["active"] != 1 {
		t.Fatalf("%v %v", got, prob)
	}
	if _, prob = s.optimizeTool(e, "del", object{"id": "goutside"}, []dnsauth.Zone{z}); prob != missing {
		t.Fatalf("unauthorized group %v", prob)
	}
}
