package dnsmcp_test

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnsauth"
)

func TestAdminOverview(t *testing.T) {
	f := setupInterface(t)
	const path = "/api/dns-overview"
	admin := session(t, f.admin)
	key := f.issue(t, admin, f.keyInput([]string{"domain.read"}, []string{"mcp"}))
	zoneSessions, err := f.app.FindCollectionByNameOrId(dnsauth.ZoneSessions)
	if err != nil {
		t.Fatal(err)
	}
	zoneSession := core.NewRecord(zoneSessions)
	zoneSession.Set("zone", f.visible.Id)
	if err := f.app.SaveNoValidate(zoneSession); err != nil {
		t.Fatal(err)
	}
	for name, authorization := range map[string]string{
		"anonymous":    "",
		"member":       session(t, f.member),
		"zone session": session(t, zoneSession),
		"interface":    key.bearer(),
	} {
		t.Run(name, func(t *testing.T) {
			w := f.request(http.MethodGet, path, authorization, "", "")
			expectDenied(t, w)
			if strings.Contains(w.Body.String(), `"domains"`) {
				t.Fatal("denied request returned overview data")
			}
		})
	}

	read := func() fields {
		t.Helper()
		w := f.request(http.MethodGet, path, admin, "", "")
		expectStatus(t, w, http.StatusOK)
		if w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), configSentinel) {
			t.Fatal("overview returned sensitive data or is cacheable")
		}
		var response struct {
			Data fields
		}
		readJSON(t, w, &response)
		return response.Data
	}
	expect := func(got fields, want string) {
		t.Helper()
		var expected fields
		if err := json.Unmarshal([]byte(want), &expected); err != nil {
			t.Fatal("invalid expected summary")
		}
		if !reflect.DeepEqual(got, expected) {
			t.Error("summary differs from the expected admin counts and metadata")
		}
	}
	expect(read(), `{
		"domains":2,"scheduled":0,
		"failover":{"total":0,"active":0,"primary":0,"backup":0,"heartbeat":null,"running":null},
		"optimization":{"total":0,"active":0,"succeeded":0,"failed":0,"heartbeat":null,"last":null},
		"orders":{"total":0,"issued":0,"failed":0,"expiring":0,"expired":0},
		"deployments":{"total":0,"pending":0,"succeeded":0,"failed":0}
	}`)

	exec := func(query string, params dbx.Params) {
		t.Helper()
		if _, err := f.app.DB().NewQuery(query).Bind(params).Execute(); err != nil {
			t.Fatal(err)
		}
	}
	add := func(collection string, values fields) string {
		t.Helper()
		col, err := f.app.FindCollectionByNameOrId(collection)
		if err != nil {
			t.Fatal(err)
		}
		record := core.NewRecord(col)
		record.Load(values)
		if err := f.app.SaveNoValidate(record); err != nil {
			t.Fatal(err)
		}
		return record.Id
	}
	exec(`INSERT INTO dns_automation_tasks(id,config,state,position) VALUES
		('active','{"kind":"failover"}','active','primary'),
		('paused','{"kind":"failover"}','paused','backup'),
		('archive','{"kind":"failover"}','archived','backup'),
		('schedule','{"kind":"schedule"}','active','primary')`, nil)
	exec(`INSERT INTO dns_optimize_tasks(id,provider,access,zone,name,family,line,config,interval,enabled,last_run,status) VALUES
		('older','cloudflare',{:access},'second','hidden.example','v4','DEF',{:secret},10,0,10,'success'),
		('latest','cloudflare',{:access},'first','allowed.example','v4','DEF',{:secret},10,1,20,'failed')`,
		dbx.Params{"access": f.account.Id, "secret": configSentinel})
	now := time.Now().UTC()
	near := add("certificate", fields{"validityNotAfter": now.AddDate(0, 0, 2), "privateKey": configSentinel})
	past := add("certificate", fields{"validityNotAfter": now.AddDate(0, 0, -1), "privateKey": configSentinel})
	exec(`INSERT INTO dns_cert_orders(id,access_id,provider,domain,algorithm,request_json,state,created,updated,certificate_id) VALUES
		('valid',{:access},'aliyun','allowed.example','EC256',{:secret},'issued',1,1,{:near}),
		('past',{:access},'aliyun','hidden.example','EC256',{:secret},'issued',1,1,{:past}),
		('cancelled',{:access},'aliyun','allowed.example','EC256',{:secret},'cancelled',1,1,''),
		('deleted',{:access},'aliyun','allowed.example','EC256',{:secret},'deleted',1,1,'')`,
		dbx.Params{"access": f.account.Id, "secret": configSentinel, "near": near, "past": past})
	workflow := add("workflow", fields{"name": "Synthetic overview fixture"})
	exec(`INSERT INTO dns_cert_deploy(id,access_id,order_id,workflow_id,node_id,status,created,remark) VALUES
		('ready',{:access},'valid',{:workflow},'node',0,1,{:secret}),
		('done',{:access},'valid',{:workflow},'node',1,1,{:secret}),
		('failed',{:access},'valid',{:workflow},'node',-1,1,{:secret})`,
		dbx.Params{"access": f.account.Id, "workflow": workflow, "secret": configSentinel})

	got := read()
	want := `{
		"domains":2,"scheduled":1,
		"failover":{"total":2,"active":1,"primary":1,"backup":1,"heartbeat":null,"running":null},
		"optimization":{"total":2,"active":1,"succeeded":1,"failed":1,"heartbeat":null,"last":{"at":20,"status":"failed"}},
		"orders":{"total":3,"issued":2,"failed":1,"expiring":1,"expired":1},
		"deployments":{"total":3,"pending":1,"succeeded":1,"failed":1}
	}`
	last := got["optimization"].(map[string]any)["last"].(map[string]any)
	for key, value := range map[string]string{"catalogId": f.visible.Id, "provider": "cloudflare", "access": f.account.Id, "zone": "first"} {
		if last[key] != value {
			t.Errorf("latest optimization result points to the wrong %s", key)
		}
		delete(last, key)
	}
	expect(got, want)

	exec(`UPDATE dnsZone SET present=0 WHERE id={:id}`, dbx.Params{"id": f.visible.Id})
	expect(read(), want)
	if f.resolutions != 0 {
		t.Fatal("overview opened a provider")
	}
}
