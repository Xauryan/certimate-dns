package dnsmcp

import (
	"context"
	"net"
	"net/http/httptest"
	"testing"

	_ "github.com/certimate-go/certimate/migrations"
	"github.com/miekg/dns"
	"github.com/pocketbase/pocketbase/core"
)

func TestCnameCatalogUsesBothZoneIdentities(t *testing.T) {
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.ResetBootstrapState() })
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	save := func(collection string, fields object) *core.Record {
		t.Helper()
		col, err := app.FindCollectionByNameOrId(collection)
		if err != nil {
			t.Fatal(err)
		}
		r := core.NewRecord(col)
		for k, v := range fields {
			r.Set(k, v)
		}
		if err := app.Save(r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	super, err := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		t.Fatal(err)
	}
	ev := &core.RequestEvent{App: app, Auth: core.NewRecord(super)}
	ev.Request = httptest.NewRequest("POST", "/mcp", nil)
	zone := func(name string) *core.Record {
		a := save("access", object{"name": "test", "provider": "cloudflare", "config": object{}})
		save("dnsAccount", object{"id": a.Id, "accessRef": a.Id})
		return save("dnsZone", object{"accountRef": a.Id, "providerZoneId": "same", "name": name, "present": true})
	}
	src := zone("example.test")
	other := zone("example.test")
	dst := zone("acme.test")
	all := scope{Zones: []string{src.Id, other.Id, dst.Id}}
	s := service{}
	add := object{"domain": "WWW.Example.test.", "did": dst.Id, "rr": "_delegated.1"}
	if _, problem := s.certCname(ev, "cert_cname_manage", "add", add, all); problem != missing {
		t.Fatalf("ambiguous source accepted: %v", problem)
	}
	add["source_zone_id"] = src.Id
	created, problem := s.certCname(ev, "cert_cname_manage", "add", add, all)
	if problem != nil {
		t.Fatal(problem)
	}
	id := created["id"]
	if _, problem := s.certCname(ev, "cert_cname_manage", "add", add, all); problem != cnameConflict {
		t.Fatalf("duplicate accepted: %v", problem)
	}
	for _, grant := range []scope{{Zones: []string{other.Id, dst.Id}}, {Zones: []string{src.Id}}} {
		rows, problem := s.certCname(ev, "cert_cname_query", "list", object{"limit": "1"}, grant)
		if problem != nil || rows["total"] != 0 {
			t.Fatalf("list exposed unauthorized row: %v %v", rows, problem)
		}
		for _, action := range []string{"edit", "check", "del"} {
			_, problem := s.certCname(ev, "cert_cname_manage", action, object{"id": id}, grant)
			if problem != missing {
				t.Fatalf("%s bypassed key scope: %v", action, problem)
			}
		}
	}
	if _, problem := s.certCname(ev, "cert_cname_manage", "edit", object{"id": id, "rr": "_validation"}, all); problem != nil {
		t.Fatal(problem)
	}
	results, problem := s.certCname(ev, "cert_cname_query", "list", object{"kw": "WWW"}, all)
	if problem != nil || results["total"] != 1 {
		t.Fatalf("authorized list: %v %v", results, problem)
	}
	row := results["rows"].([]certCnameRow)[0]
	if row.Host != "_acme-challenge.www" || row.Record != "_validation.acme.test" || row.Status != 0 {
		t.Fatalf("wrong CNAME projection: %+v", row)
	}
	dst.Set("present", false)
	if err := app.Save(dst); err != nil {
		t.Fatal(err)
	}
	results, problem = s.certCname(ev, "cert_cname_query", "list", object{}, all)
	if problem != nil || results["total"] != 0 {
		t.Fatalf("stale grant exposed row: %v %v", results, problem)
	}
}

func TestCnameCheckReadsDirectAnswer(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: conn, Net: "udp", NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		r.Rcode = dns.RcodeNameError
		rr := &dns.CNAME{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "TARGET.example.test."}
		r.Answer = []dns.RR{rr}
		_ = w.WriteMsg(r)
	})}
	go srv.ActivateAndServe()
	<-started
	t.Cleanup(func() { srv.Shutdown() })
	for _, tc := range []struct {
		target string
		want   bool
	}{{"target.example.test", true}, {"different.example.test", false}} {
		got, err := publishedCnameAt(context.Background(), conn.LocalAddr().String(), "_acme-challenge.source.test", tc.target)
		if err != nil || got != tc.want {
			t.Fatalf("%s: got %v (%v)", tc.target, got, err)
		}
	}
}
