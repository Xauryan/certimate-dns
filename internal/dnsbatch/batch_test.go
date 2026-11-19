package dnsbatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/certimate-go/certimate/migrations"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
)

type batchProvider struct {
	dns.Provider
	afterList func()
	rows      []dns.DNSRecord
	writes    int
	unknown   bool
}

func (p *batchProvider) DNSRecords(ctx context.Context, zone string, page int, filter string) (*dns.DNSPage[dns.DNSRecord], error) {
	if zone != "upstream" || page != 1 {
		return nil, errors.New("unexpected query")
	}
	if p.afterList != nil {
		p.afterList()
	}
	return &dns.DNSPage[dns.DNSRecord]{Items: p.rows, Info: dns.PageInfo{Page: 1, Total: len(p.rows)}}, nil
}
func (p *batchProvider) CreateDNSRecord(_ context.Context, zone string, c dns.RecordInput) (string, error) {
	if zone != "upstream" {
		return "", errors.New("wrong scope")
	}
	p.writes++
	id := fmt.Sprint("new-", p.writes)
	p.rows = append(p.rows, dns.DNSRecord{ID: id, Type: c.Type, Name: c.Name, Content: c.Content, TTL: c.TTL, Line: c.Line, Priority: c.Priority, Weight: c.Weight, Description: c.Description})
	if p.unknown {
		return "", errors.New("lost response")
	}
	return id, nil
}
func (p *batchProvider) PatchDNSRecord(_ context.Context, zone, id string, c dns.RecordPatch) (string, error) {
	r := byID(p.rows, id)
	if zone != "upstream" || r == nil {
		return "", errors.New("wrong scope")
	}
	p.writes++
	r.ID = "replaced-" + id
	r.Content = c.Content
	r.TTL = c.TTL
	return r.ID, nil
}

func testApp(t *testing.T) *core.BaseApp {
	t.Helper()
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.ResetBootstrapState() })
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	return app
}

var zoneScope = scope{provider: "aliyun", access: "access1", zone: "upstream", actor: "member/one"}

const origin = "example.test"

func allowBatch() error { return nil }

func previewPlan(t *testing.T, db dbx.Builder, p dns.Provider, changes []Change) *Plan {
	t.Helper()
	rows, err := zoneRecords(t.Context(), p, zoneScope.zone, origin)
	if err != nil {
		t.Fatal(err)
	}
	items, _, err := prepare(t.Context(), p, zoneScope.provider, zoneScope.zone, origin, rows, changes)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := saveNew(db, zoneScope, changes, items)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
func TestClaimDriftAndReplacementID(t *testing.T) {
	db := testApp(t).DB()
	record := dns.DNSRecord{ID: "1", Type: "TXT", Name: "one." + origin, Content: "synthetic-record-one", TTL: 300}
	p := &batchProvider{rows: []dns.DNSRecord{record}}
	changes := []Change{{Action: "patch", ID: "1", Content: "synthetic-record-two", TTL: 60}}
	plan := previewPlan(t, db, p, changes)
	wrong := zoneScope
	wrong.access = "access2"
	if _, err := loadPlan(db, wrong, plan.ID); !errors.Is(err, errMissing) {
		t.Fatal("loaded plan for another account")
	}
	wrong = zoneScope
	wrong.actor = "member/two"
	allow := func() error { return nil }
	if err := plan.apply(t.Context(), db, p, wrong, origin, changes, allow); !errors.Is(err, errConflict) {
		t.Fatal("another actor could apply")
	}
	otherPlan, err := loadPlan(db, zoneScope, plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	p.rows[0].TTL++
	if err := plan.apply(t.Context(), db, p, zoneScope, origin, changes, allow); err != nil {
		t.Fatal(err)
	}
	if p.writes != 0 || plan.Items[0].State != "conflict" {
		t.Fatal("stale item reached provider")
	}
	if err := otherPlan.apply(t.Context(), db, p, zoneScope, origin, changes, allow); !errors.Is(err, errConflict) {
		t.Fatal("old revision reclaimed")
	}
	plan = previewPlan(t, db, p, changes)
	if err := plan.apply(t.Context(), db, p, zoneScope, origin, changes, allow); err != nil {
		t.Fatal(err)
	}
	if p.writes != 1 || plan.State != "completed" || plan.Items[0].ID != "replaced-1" {
		t.Fatalf("missing replacement: %+v", plan.public())
	}
	var items string
	if err := db.Select("items").From("dns_batch_plans").Where(dbx.HashExp{"id": plan.ID}).Row(&items); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(items, "synthetic-record") {
		t.Fatal("record values persisted in history")
	}
	out, err := json.Marshal(plan.public())
	if err != nil || strings.Contains(string(out), "before") {
		t.Fatal("digest exposed in history")
	}
}
func TestUncertainCreateReconcilesExactLineWithoutReplay(t *testing.T) {
	db := testApp(t).DB()
	p := &batchProvider{unknown: true}
	change := Change{Action: "create", Name: "www." + origin, Type: "A", Content: "127.0.0.2", TTL: 60, Line: "telecom"}
	changes := []Change{change, {Action: "create", Name: "second." + origin, Type: "TXT", Content: "test", TTL: 60}}
	p.rows = []dns.DNSRecord{{ID: "other-line", Name: change.Name, Type: change.Type, Content: change.Content, TTL: 60, Line: "default"}}
	plan := previewPlan(t, db, p, changes)
	if err := plan.apply(t.Context(), db, p, zoneScope, origin, changes, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if p.writes != 1 || plan.State != "uncertain" || plan.Items[1].State != "not_sent" {
		t.Fatal("uncertain dispatch was retried or continued")
	}
	loaded, err := loadPlan(db, zoneScope, plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.reconcile(t.Context(), db, p, zoneScope, origin, allowBatch); err != nil {
		t.Fatal(err)
	}
	if p.writes != 1 || loaded.State != "partial" || loaded.Items[0].State != "observed" || loaded.Items[0].ID != "new-1" {
		t.Fatal("reconciliation selected another line or repeated a write")
	}
}
func TestRecheckAuthorizationBeforeDispatch(t *testing.T) {
	db := testApp(t).DB()
	p := &batchProvider{}
	change := []Change{{Action: "create", Name: origin, Type: "TXT", Content: "aaa", TTL: 60}}
	plan := previewPlan(t, db, p, change)
	revoked := errors.New("revoked")
	count := 0
	err := plan.apply(t.Context(), db, p, zoneScope, origin, change, func() error {
		count++
		if count == 2 {
			return revoked
		}
		return nil
	})
	if !errors.Is(err, revoked) || p.writes != 0 || plan.Items[0].State != "not_sent" {
		t.Fatal("write after revocation")
	}
}
func TestProtectedRecordsAndFileBoundaries(t *testing.T) {
	p := &batchProvider{}
	for _, r := range []dns.DNSRecord{
		{ID: "a", Name: "www." + origin, Type: "A", ReadOnly: true},
		{ID: "a", Name: "wrong.test", Type: "A"},
		{ID: "a", Name: origin, Type: "NS"},
	} {
		_, _, err := prepare(t.Context(), p, "aliyun", "upstream", origin, []dns.DNSRecord{r}, []Change{{ID: "a", Action: "delete"}})
		if err == nil {
			t.Fatal("protected or foreign record accepted")
		}
	}
	for _, file := range []string{
		"$INCLUDE other.zone\n",
		"$GENERATE 1-200 x$ IN A 127.0.0.1\n",
		"outside.test. 60 IN A 127.0.0.1\n",
		"www 60 IN TXT \"first\" \"second\"\n",
		"www 60 IN A 127.0.0.1 ; cf_tags=cf-proxied:true\n",
	} {
		if _, err := importZone(file, origin); err == nil {
			t.Fatal("unsupported input accepted")
		}
	}
	in := "$TTL 60\n@ IN TXT \"hello there\"\nwww IN CNAME @\n"
	items, err := importZone(in, origin)
	if err != nil || len(items) != 2 || items[1].Content != origin {
		t.Fatalf("valid BIND: %v", err)
	}
	var rows []dns.DNSRecord
	for _, c := range items {
		rows = append(rows, dns.DNSRecord{Name: c.Name, Type: c.Type, Content: c.Content, TTL: c.TTL})
	}
	out, err := exportZone(rows, origin)
	if err != nil {
		t.Fatal(err)
	}
	again, err := importZone(out, origin)
	if err != nil || digest(again) != digest(items) {
		t.Fatal("zone file round trip failed")
	}
	rows[0].Description = "meta"
	if _, err := exportZone(rows, origin); err == nil {
		t.Fatal("silently discarded metadata")
	}
}

func TestBoundRoutesScopeBeforeProviderAndPagination(t *testing.T) {
	app := testApp(t)
	add := func(name string, vals map[string]any) *core.Record {
		c, err := app.FindCollectionByNameOrId(name)
		if err != nil {
			t.Fatal(err)
		}
		r := core.NewRecord(c)
		for k, v := range vals {
			r.Set(k, v)
		}
		if err := app.Save(r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	member := add("dns_members", map[string]any{"email": "batch@example.test", "password": "synthetic-test-password"})
	auth, err := member.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	account := add("access", map[string]any{"name": "DNS batch test", "provider": "aliyun", "config": map[string]string{}})
	add("dnsAccount", map[string]any{"id": account.Id, "accessRef": account.Id})
	zone := add("dnsZone", map[string]any{"accountRef": account.Id, "providerZoneId": "upstream", "name": origin, "present": true})
	grant := add("dns_zone_grants", map[string]any{"member": member.Id, "zone": zone.Id, "role": "reader"})
	second := add("access", map[string]any{"name": "Other DNS batch account", "provider": "aliyun", "config": map[string]string{}})
	add("dnsAccount", map[string]any{"id": second.Id, "accessRef": second.Id})
	otherZone := add("dnsZone", map[string]any{"accountRef": second.Id, "providerZoneId": "upstream", "name": origin, "present": true})
	otherProvider := &replacementProvider{attributedProvider: attributedProvider{batchProvider: batchProvider{rows: []dns.DNSRecord{
		{ID: "1", Name: "host01." + origin, Type: "TXT", TTL: 300, Content: "other-account-record"},
	}}}}
	p := &batchProvider{}
	for n := 1; n <= 22; n++ {
		p.rows = append(p.rows, dns.DNSRecord{ID: fmt.Sprint(n), Name: fmt.Sprintf("host%02d.%s", n, origin), Type: "TXT", Content: "synthetic-record", TTL: n})
	}
	routes, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	Bind(routes.Group("/api"), func(_ context.Context, provider, access string, _ bool) (dns.Provider, error) {
		calls++
		if provider == "aliyun" {
			switch access {
			case account.Id:
				return p, nil
			case second.Id:
				return otherProvider, nil
			}
		}
		return nil, errors.New("wrong account")
	})
	mux, err := routes.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	type response struct {
		Code int
		Data json.RawMessage
	}
	requestAccount := func(access, token, method, path, body string) response {
		t.Helper()
		req := httptest.NewRequest(method, "/api/dns/aliyun/"+access+"/zones/upstream/batch"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", token)
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		var out response
		if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	request := func(token, method, path, body string) response {
		return requestAccount(account.Id, token, method, path, body)
	}
	if got := request("", "GET", "/features", ""); got.Code != 401 || calls != 0 {
		t.Fatal("unauthenticated provider access")
	}
	if got := request(auth, "POST", "/preview", `{"changes":[{"action":"delete","id":"1"}]}`); got.Code != 403 || calls != 0 {
		t.Fatal("reader could preview writes")
	}
	got := request(auth, "GET", "/search?page=2&sort=ttl&order=desc", "")
	var rows dns.DNSPage[dns.DNSRecord]
	if got.Code != 0 || json.Unmarshal(got.Data, &rows) != nil || len(rows.Items) != 2 || rows.Items[0].TTL != 2 || rows.Info.Total != 22 {
		t.Fatal("cross-page sort or total wrong")
	}
	got = request(auth, "GET", "/export?format=archive", "")
	var backup zoneArchive
	if got.Code != 0 || json.Unmarshal(got.Data, &backup) != nil || backup.Schema != "certimate.dns.zone" || backup.Version != 1 || backup.AccessID != account.Id || len(backup.Records) != len(p.rows) {
		t.Fatal("invalid versioned archive")
	}
	p.afterList = func() {
		if err := app.Delete(grant); err != nil {
			t.Fatal(err)
		}
	}
	if got := request(auth, "GET", "/export?format=json", ""); got.Code != 404 || string(got.Data) != "null" {
		t.Fatal("export delivered after access was revoked")
	}
	if got := request(auth, "GET", "/history", ""); got.Code != 404 || calls != 3 {
		t.Fatal("revoked grant still reached provider")
	}
	if got := requestAccount(second.Id, auth, "GET", "/search", ""); got.Code != 404 || calls != 3 {
		t.Fatal("colliding provider zone ID authorized another account")
	}
	add("dns_zone_grants", map[string]any{"member": member.Id, "zone": zone.Id, "role": "editor"})
	add("dns_zone_grants", map[string]any{"member": member.Id, "zone": otherZone.Id, "role": "editor"})
	p.afterList = nil
	got = requestAccount(second.Id, auth, "GET", "/features", "")
	var feature struct{ Edit dns.RecordEditCapabilities }
	if got.Code != 0 || json.Unmarshal(got.Data, &feature) != nil || !feature.Edit.Rename {
		t.Fatal("replacement capability missing from scoped account")
	}
	changes := `{"changes":[{"action":"replace","id":"1","name":"renamed.example.test","type":"MX","content":"mail.example.test","priority":0}]}`
	got = requestAccount(second.Id, auth, "POST", "/preview", changes)
	var review struct {
		Plan Plan
		Rows []PreviewRow
	}
	if got.Code != 0 || json.Unmarshal(got.Data, &review) != nil || len(review.Rows) != 1 {
		t.Fatalf("preview did not use the selected account: %+v", got)
	}
	row := review.Rows[0]
	if row.Before == nil || row.Before.Content != "other-account-record" || row.After == nil || row.After.Name != "renamed.example.test" || row.After.Type != "MX" || row.After.Priority == nil || *row.After.Priority != 0 {
		t.Fatalf("preview did not show the scoped source and effective replacement: %+v", row)
	}
	applyPath := "/plans/" + review.Plan.ID + "/apply"
	confirm := `{"confirm":true,` + changes[1:]
	if got := request(auth, "POST", applyPath, confirm); got.Code != 404 || p.writes != 0 || otherProvider.writes != 0 {
		t.Fatal("plan applied through an account with the same remote zone and record ID")
	}
	got = request(auth, "GET", "/history", "")
	var history struct{ Total int }
	if got.Code != 0 || json.Unmarshal(got.Data, &history) != nil || history.Total != 0 {
		t.Fatal("plan history crossed account boundaries")
	}
	got = requestAccount(second.Id, auth, "POST", applyPath, confirm)
	var applied Plan
	if got.Code != 0 || json.Unmarshal(got.Data, &applied) != nil || applied.State != "completed" || applied.Items[0].ID != "replaced-1" || p.writes != 0 || otherProvider.writes != 1 {
		t.Fatalf("did not verify the replacement in the selected account: %+v", got)
	}
}

type attributedProvider struct {
	batchProvider
	attrs      map[string]string
	group      string
	omitRemark bool
}

func (p *attributedProvider) BatchFields() []string { return []string{"status", "weight", "remark"} }
func (p *attributedProvider) BatchAttribute(_ context.Context, _, id, field string) (string, error) {
	if byID(p.rows, id) == nil {
		return "", errors.New("missing row")
	}
	return p.attrs[field], nil
}
func (p *attributedProvider) SetBatchAttribute(_ context.Context, _, id, field, value string) error {
	if byID(p.rows, id) == nil {
		return errors.New("missing row")
	}
	p.writes++
	if !p.omitRemark || field != "remark" {
		p.attrs[field] = value
	}
	return nil
}
func (p *attributedProvider) BatchGroups(context.Context, string) ([]Group, error) {
	return []Group{{ID: "g", Name: "Test"}}, nil
}
func (p *attributedProvider) BatchGroup(context.Context, string, string) (string, error) {
	return p.group, nil
}
func (p *attributedProvider) SetBatchGroup(_ context.Context, _, id, value string) error {
	if byID(p.rows, id) == nil || value != "g" {
		return errors.New("missing target")
	}
	p.writes++
	p.group = value
	return nil
}
func TestRichCreateReadbackAndProjection(t *testing.T) {
	db := testApp(t).DB()
	priority, weight := 20, 10
	change := []Change{{Action: "create", Name: origin, Type: "MX", Content: "mail." + origin, TTL: 60, Priority: &priority, Weight: &weight, Line: "telecom", Description: "synthetic note", Status: "disabled", Group: "g"}}
	p := &attributedProvider{attrs: map[string]string{}}
	plan := previewPlan(t, db, p, change)
	if err := plan.apply(t.Context(), db, p, zoneScope, origin, change, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if plan.State != "completed" || p.writes != 5 || p.rows[0].Priority == nil || *p.rows[0].Priority != 20 || p.group != "g" || p.attrs["status"] != "disabled" || p.attrs["weight"] != "10" || p.attrs["remark"] != "synthetic note" {
		t.Fatalf("incomplete metadata: %+v", plan.public())
	}
	change[0].Group = "other"
	if _, _, err := prepare(t.Context(), p, "aliyun", "upstream", origin, nil, change); err == nil {
		t.Fatal("unknown group accepted")
	}
	change[0].Group = "g"
	p = &attributedProvider{attrs: map[string]string{}, omitRemark: true}
	plan = previewPlan(t, db, p, change)
	if err := plan.apply(t.Context(), db, p, zoneScope, origin, change, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if plan.State != "uncertain" {
		t.Fatal("missing remark was reported as applied")
	}
	before := p.writes
	if err := plan.reconcile(t.Context(), db, p, zoneScope, origin, allowBatch); err != nil || plan.State != "uncertain" || p.writes != before {
		t.Fatal("reconcile retried or omitted missing metadata")
	}
	p.attrs["remark"] = "synthetic note"
	if err := plan.reconcile(t.Context(), db, p, zoneScope, origin, allowBatch); err != nil || plan.State != "completed" || p.writes != before {
		t.Fatal("completed metadata not observed")
	}
}
