package dnsmigrate

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"

	"github.com/pocketbase/dbx"

	"github.com/certimate-go/certimate/internal/dnsautomation"
	"github.com/certimate-go/certimate/internal/dnsoptimize"
)

func TestTaskPromotionValidatesTargetsWithoutExecuting(t *testing.T) {
	db, err := dbx.Open("sqlite", filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(q string, params dbx.Params) {
		t.Helper()
		if _, err := db.NewQuery(q).Bind(params).Execute(); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE TABLE dns_automation_tasks(id TEXT PRIMARY KEY,config TEXT,state TEXT,lease TEXT);
	CREATE TABLE access(id TEXT PRIMARY KEY,provider TEXT,deleted TEXT);
	INSERT INTO access VALUES ('owner','aliyun','');
	CREATE TABLE dns_optimize_tasks(id TEXT PRIMARY KEY, config TEXT,enabled INTEGER,lease INTEGER,name TEXT,family TEXT,line TEXT,access TEXT,zone TEXT,provider TEXT)`, nil)
	z := Zone{ID: 1, Name: "example.test"}
	parent := Item{Kind: "domain", Legacy: 1, Target: "localzone", AccountID: "owner", ProviderZone: "example.test", details: z}
	p := planner{ctx: t.Context(), db: db, manifest: &Manifest{Timezone: "UTC"}, report: Report{Items: []Item{parent}}}
	check := func(t *testing.T, b Promotion, i Item, previous, conflict bool) {
		t.Helper()
		work, err := p.planTaskPromotion(b, i, previous)
		if err != nil || work.Apply != nil || (work.Conflict != "") != conflict {
			t.Fatalf("unexpected %s binding: conflict=%q err=%v", i.Kind, work.Conflict, err)
		}
	}
	t.Run("schedule identity and state", func(t *testing.T) {
		task := Task{Kind: "sctask", ID: 1, ZoneID: 1, RR: "@", Record: "r1", Schedule: &Schedule{Action: 2, Mode: 1, Cycle: 1, Day: "0", At: "09:00"}}
		i := Item{Kind: task.Kind, details: task}
		b := Promotion{Kind: task.Kind, LegacyID: 1, TargetID: "schedule", Confirm: true}
		d := dnsautomation.Definition{Kind: "schedule", Action: "disable", Target: dnsautomation.Target{AccountID: "owner", ZoneID: "example.test", Name: "EXAMPLE.test.", RecordID: "r1", Type: "A"}, Schedule: dnsautomation.Schedule{Cycle: "weekly", At: "09:00", Timezone: "UTC"}}
		save := func(state, lease string) {
			data, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			exec("INSERT OR REPLACE INTO dns_automation_tasks VALUES ('schedule',{:config},{:state},{:lease})", dbx.Params{"config": data, "state": state, "lease": lease})
		}
		save("draft", "")
		check(t, b, i, false, false)
		save("active", "")
		check(t, b, i, false, true)
		check(t, b, i, true, false)
		save("paused", "held")
		check(t, b, i, false, true)
		d.Target.RecordID = "other"
		save("paused", "")
		check(t, b, i, false, true)
		d.Target.RecordID = "r1"
		d.Target.AccountID = "foreign"
		save("draft", "")
		check(t, b, i, true, true)
		d.Target.AccountID = "owner"
		d.Schedule.Day = 1
		save("draft", "")
		check(t, b, i, false, true)
	})
	t.Run("alias links only to its parent", func(t *testing.T) {
		i := Item{Kind: "domain_alias", details: Related{ParentID: 1, Domain: "alias.test"}}
		b := Promotion{Kind: i.Kind, LegacyID: 2, TargetID: parent.Target, Confirm: true}
		check(t, b, i, false, false)
		b.TargetID = "other"
		check(t, b, i, false, true)
	})
	t.Run("complete optimization group", func(t *testing.T) {
		task := Task{Kind: "optimizeip", ID: 2, ZoneID: 1, RR: "cdn", Optimize: &Optimize{Mode: 1, Family: "v6,v4", CDN: 2, Count: 2, TTL: 600}}
		i := Item{Kind: task.Kind, details: task}
		ids := []string{}
		for _, family := range []string{"v6", "v4"} {
			for _, line := range []string{"CT", "CU", "CM"} {
				target := line
				if line == "CT" {
					target = "DEF"
				}
				id := family + line
				spec := dnsoptimize.Spec{Name: "cdn.example.test", Source: "wetest", CDN: "cloudfront", Family: family, SourceLine: line, TargetLine: target, TTL: 600, Ranks: []int{1, 2}}
				data, err := json.Marshal(spec)
				if err != nil {
					t.Fatal(err)
				}
				exec(`INSERT INTO dns_optimize_tasks VALUES ({:id},{:cfg},0,0,'cdn.example.test',{:family},{:line},'owner','example.test','aliyun')`, dbx.Params{"id": id, "cfg": data, "family": family, "line": target})
				ids = append(ids, id)
			}
		}
		b := Promotion{Kind: i.Kind, LegacyID: 2, TargetID: ids[0], AdditionalTargets: ids[1:], Confirm: true}
		original := slices.Clone(b.AdditionalTargets)
		bindings := Bindings{Promotions: []Promotion{b}}
		if err := bindings.validatePromotions(); err != nil || !slices.Equal(b.AdditionalTargets, original) {
			t.Fatal("promotion validation changed the caller's binding or rejected the complete target set")
		}
		check(t, b, i, false, false)
		incomplete := b
		incomplete.AdditionalTargets = ids[2:]
		check(t, incomplete, i, false, true)
		exec("UPDATE dns_optimize_tasks SET enabled=1 WHERE id='v4CU'", nil)
		check(t, b, i, false, true)
		check(t, b, i, true, false)
		exec("UPDATE dns_optimize_tasks SET zone='foreign' WHERE id='v4CU'", nil)
		check(t, b, i, true, true)
	})
}

func TestMonitorPromotionRetainsActionAndThreshold(t *testing.T) {
	d := dnsautomation.Definition{Kind: "failover", Action: "standby", Monitor: dnsautomation.Monitor{Interval: 10, HealthyLimit: 2}}
	f := Monitor{Action: 3, Frequency: 10, Cycles: 2}
	if !matchesSourceMonitor(f, d) {
		t.Fatal("matching standby task rejected")
	}
	d.Monitor.HealthyLimit = 3
	if matchesSourceMonitor(f, d) {
		t.Fatal("standby threshold mismatch accepted")
	}
}
