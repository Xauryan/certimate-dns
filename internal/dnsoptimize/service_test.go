package dnsoptimize

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"

	_ "github.com/certimate-go/certimate/migrations"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type memoryProvider struct {
	dns.Provider
	rows   []dns.DNSRecord
	writes int
}

func (p *memoryProvider) DNSRecords(_ context.Context, _ string, page int, _ string) (*dns.DNSPage[dns.DNSRecord], error) {
	return &dns.DNSPage[dns.DNSRecord]{Items: slices.Clone(p.rows), Info: dns.PageInfo{Page: page, Total: len(p.rows)}}, nil
}
func (p *memoryProvider) CreateDNSRecord(_ context.Context, _ string, in dns.RecordInput) (string, error) {
	p.writes++
	id := fmt.Sprintf("new-%d", p.writes)
	p.rows = append(p.rows, dns.DNSRecord{ID: id, Name: in.Name, Type: in.Type, Content: in.Content, TTL: in.TTL, Line: in.Line})
	return id, nil
}
func (p *memoryProvider) PatchDNSRecord(_ context.Context, _, id string, patch dns.RecordPatch) (string, error) {
	for i := range p.rows {
		if p.rows[i].ID == id {
			p.writes++
			p.rows[i].TTL, p.rows[i].Content = patch.TTL, patch.Content
			return id, nil
		}
	}
	return "", errors.New("unknown record")
}
func (p *memoryProvider) DeleteDNSRecord(_ context.Context, _, id string) (string, error) {
	for i := range p.rows {
		if p.rows[i].ID == id {
			p.writes++
			p.rows = slices.Delete(p.rows, i, i+1)
			return id, nil
		}
	}
	return "", errors.New("unknown record")
}
func (p *memoryProvider) SetRankedAddresses(ctx context.Context, zone, id string, in dns.RecordInput, values []string) (string, error) {
	in.Content = strings.Join(values, "\n")
	if id == "" {
		return p.CreateDNSRecord(ctx, zone, in)
	}
	return p.PatchDNSRecord(ctx, zone, id, dns.RecordPatch{Content: in.Content, TTL: in.TTL})
}
func spec() Spec {
	return Spec{Name: "cdn.example.test", Source: "xingpingcn", CDN: "cloudflare", Family: "v4", SourceLine: "CT", TargetLine: "DEF", TTL: 300, Ranks: []int{1, 2}}
}

func TestPlannerScopeAndReadback(t *testing.T) {
	ctx := t.Context()
	target := Target{"aliyun", "account", "example.test"}
	s := spec()
	feed := candidates{"CT": {"1.1.1.1", "8.8.8.8"}}
	p := &memoryProvider{rows: []dns.DNSRecord{
		{ID: "other", Name: s.Name, Type: "A", Content: "9.9.9.9", TTL: 3600, Line: "mobile"},
		{ID: "cname", Name: s.Name, Type: "CNAME", Content: "backend.example.test", TTL: 300, Line: "default"},
	}}
	if _, err := matchingRecords(ctx, p, target, s); err == nil {
		t.Fatal("unapproved CNAME replacement")
	}
	s.ReplaceCNAME = true
	rr, err := matchingRecords(ctx, p, target, s)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := buildPlan(target, s, feed, rr)
	if err != nil || len(plan.Changes) != 3 || plan.Changes[0].Action != "delete" {
		t.Fatalf("CNAME plan: %+v %v", plan, err)
	}
	if err := applyPlan(ctx, p, target, s, plan); err != nil {
		t.Fatal(err)
	}
	if p.writes != 3 || p.rows[0].ID != "other" || p.rows[0].TTL != 3600 {
		t.Fatal("another line was touched")
	}
	rr, err = matchingRecords(ctx, p, target, s)
	if err != nil {
		t.Fatal(err)
	}
	again, err := buildPlan(target, s, feed, rr)
	if err != nil || len(again.Changes) != 0 {
		t.Fatal("unexpected writes on retry")
	}
	p.rows[1].ReadOnly = true
	if _, err := matchingRecords(ctx, p, target, s); err == nil {
		t.Fatal("protected row accepted")
	}
}
func TestHuaweiRankedSet(t *testing.T) {
	target := Target{"huaweicloud", "account", "opaque-zone"}
	s := spec()
	feed := candidates{"CT": {"8.8.8.8", "1.1.1.1"}}
	p := &memoryProvider{rows: []dns.DNSRecord{{ID: "set", Name: s.Name, Type: "A", Content: "1.1.1.1\n9.9.9.9", TTL: 300, Line: "default_view"}}}
	rr, err := matchingRecords(t.Context(), p, target, s)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := buildPlan(target, s, feed, rr)
	if err != nil || len(plan.Changes) != 1 || plan.Changes[0].ID != "set" {
		t.Fatalf("%v %+v", err, plan)
	}
	if err = applyPlan(t.Context(), p, target, s, plan); err != nil {
		t.Fatal(err)
	}
	if p.writes != 1 || p.rows[0].Content != "1.1.1.1\n8.8.8.8" {
		t.Fatalf("record set: %+v", p.rows)
	}
}

func TestRealStorageAndScheduler(t *testing.T) {
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.ResetBootstrapState() })
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	save := func(collection string, fields map[string]any) *core.Record {
		c, err := app.FindCollectionByNameOrId(collection)
		if err != nil {
			t.Fatal(err)
		}
		r := core.NewRecord(c)
		for k, v := range fields {
			r.Set(k, v)
		}
		if err := app.Save(r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	a := save("access", map[string]any{"name": "mock account", "provider": "aliyun", "config": map[string]string{"accessKeyId": "synthetic-test"}})
	acct := save("dnsAccount", map[string]any{"id": a.Id, "accessRef": a.Id})
	save("dnsZone", map[string]any{"accountRef": a.Id, "providerZoneId": "opaque", "name": "example.test", "present": true})
	target := Target{"aliyun", a.Id, "opaque"}
	p := &memoryProvider{}
	s := New(app, func(_ context.Context, provider, access, zone string) (dns.Provider, error) {
		if provider != target.Provider || access != target.Access || zone != target.Zone {
			t.Fatal("zone binding lost")
		}
		return p, nil
	})
	s.fetch = func(context.Context, Feed) (candidates, error) { return candidates{"CT": {"1.1.1.1", "8.8.8.8"}}, nil }
	ctx := t.Context()
	if s.LastTick() != 0 {
		t.Fatal("optimizer has a heartbeat before its first scan")
	}
	s.runDue(ctx)
	if s.LastTick() <= 0 || p.writes != 0 {
		t.Fatal("an empty scheduler scan should update the heartbeat without DNS writes")
	}
	in := spec()
	in.Name = "bad.other.test"
	if _, err := s.SaveTask(ctx, target, in, 10, ""); err == nil {
		t.Fatal("out-of-zone owner accepted")
	}
	in = spec()
	id, err := s.SaveTask(ctx, target, in, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := s.Preview(ctx, target, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.RunTask(ctx, target, id, "synthetic-admin", strings.Repeat("0", 64)); err == nil || p.writes != 0 {
		t.Fatal("stale confirmation led to changes")
	}
	if _, err = s.RunTask(ctx, target, id, "synthetic-admin", plan.Digest); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListTasks(ctx, target)
	if err != nil || len(rows) != 1 || rows[0].Status != "success" || rows[0].Enabled {
		t.Fatalf("unexpected status: %v %+v", err, rows)
	}
	plan, err = s.Preview(ctx, target, in)
	if err != nil {
		t.Fatal(err)
	}
	change, err := s.ReviewTask(ctx, target, id, true, plan.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveTask(ctx, target, in, 20, id); err != nil {
		t.Fatal(err)
	}
	if err := app.RunInTransaction(change); err == nil {
		t.Fatal("stale task config enabled")
	}
	if err = s.SetEnabled(ctx, target, id, true, plan.Digest); err != nil {
		t.Fatal(err)
	}
	query := func(q string) {
		if _, err := app.DB().NewQuery(q).Execute(); err != nil {
			t.Fatal(err)
		}
	}
	query("UPDATE dns_optimize_tasks SET due=0")
	p.rows = nil
	s.runDue(ctx)
	if p.writes != 4 {
		t.Fatalf("expected one scheduled reconciliation: %d", p.writes)
	}
	s.runDue(ctx)
	if p.writes != 4 {
		t.Fatal("schedule executed before next due time")
	}
	acct.Set("disabled", true)
	if err := app.Save(acct); err != nil {
		t.Fatal(err)
	}
	query("UPDATE dns_optimize_tasks SET due=0")
	p.rows = nil
	s.runDue(ctx)
	if p.writes != 4 {
		t.Fatal("disabled account performed a write")
	}
	var state string
	if err := app.DB().NewQuery("SELECT status FROM dns_optimize_tasks").Row(&state); err != nil || state != "failed" {
		t.Fatal("missing failed task state", err, state)
	}
	r, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	s.Bind(r.Group("/api"))
	mux, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"tasks", "candidates", "quota", "history"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/dns/aliyun/"+a.Id+"/zones/opaque/optimize/"+action, nil))
		if rec.Code != 401 {
			t.Fatalf("anonymous %s status %d", action, rec.Code)
		}
	}
	s.Start()
	s.Start()
	s.Stop()
	s.Stop()
}

type roundTrip func(*http.Request) (*http.Response, error)

func (r roundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return r(req) }
func TestNamedFeedAndQuota(t *testing.T) {
	ctx := t.Context()
	feeds := defaultFeedClient()
	const key = "synthetic+&/key"
	feeds.key = func(string) string { return key }
	var calls int
	feeds.client.Transport = roundTrip(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Scheme != "https" || req.URL.Host != "www.wetest.vip" {
			t.Fatal("unexpected feed host")
		}
		payload := ""
		switch req.URL.Path {
		case "/api/cf2dns/get_license":
			if req.URL.Query().Get("license") != key {
				t.Fatal("missing license")
			}
			payload = `{"code":200,"count":"18"}`
		case "/api/cf2dns/get_gcore_ip":
			if req.Method != "POST" {
				t.Fatal("expected POST")
			}
			payload = `{"code":200,"info":{"CT":[{"ip":"1.1.1.1"},{"ip":"1.1.1.1"},{"ip":"10.0.0.1"},{"ip":"::1"},{"ip":"8.8.8.8"}]}}`
		default:
			t.Fatal("unexpected path")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(payload)), Header: make(http.Header)}, nil
	})
	s := &Service{feedClient: feeds}
	q, err := s.Quota(ctx, "xingpingcn")
	if err != nil || !q.Unlimited || calls != 0 {
		t.Fatal("free quota performed network request")
	}
	q, err = s.Quota(ctx, "wetest")
	if err != nil || q.Remaining != 18 {
		t.Fatal("paid quota", q, err)
	}
	ips, err := feeds.load(ctx, Feed{"wetest", "gcore", "v4"})
	if err != nil || !slices.Equal(ips["CT"], []string{"1.1.1.1", "8.8.8.8"}) {
		t.Fatalf("%v %#v", err, ips)
	}
	if _, err := feeds.load(ctx, Feed{"http://example.test", "cloudflare", "v4"}); err == nil || calls != 2 {
		t.Fatal("unsupported feed was fetched")
	}
	feeds.client.Transport = roundTrip(func(req *http.Request) (*http.Response, error) { return nil, errors.New(req.URL.String()) })
	if _, err := s.Quota(ctx, "wetest"); err == nil || strings.Contains(err.Error(), "license=") {
		t.Fatal("quota error disclosed its URL")
	}
}
