package henet

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestNativeEditKeepsIdentityAndRefusesConflicts(t *testing.T) {
	owner := "mail.example.test"
	records := row("11", owner, "MX", "7", "mx.example.test.") + row("12", "other.example.test", "A", "", "127.0.0.2")
	var updates int
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<table id="domains_table"><tr><td><input onclick="delete_dom(this);" name="example.test" value="51"></td></tr></table>`)
			return
		}
		if r.Method == "GET" {
			fmt.Fprint(w, "<table>"+records+"</table>")
			return
		}
		updates++
		if r.FormValue("hosted_dns_recordid") != "11" || r.FormValue("hosted_dns_editrecord") != "Update" || r.FormValue("hosted_dns_zoneid") != "51" {
			t.Error("expected a single native update")
		}
		records = row("11", r.FormValue("Name"), r.FormValue("Type"), r.FormValue("Priority"), r.FormValue("Content")) + row("12", "other.example.test", "A", "", "127.0.0.2")
		fmt.Fprint(w, `<div id="dns_status">Successfully updated record.</div><table>`+records+"</table>")
	}))
	defer s.Close()
	p := &provider{s.URL + "/", "fixture-user", "fixture-password", s.Client()}
	ctx := context.Background()
	pg, err := p.DNSRecords(ctx, "51", 1, owner)
	if err != nil {
		t.Fatal(err)
	}
	prior := pg.Items[0]
	stale := prior
	stale.Content = "obsolete"
	n := 18
	next := dns.RecordInput{Type: "MX", Name: "mail2.example.test", Content: "exchange.example.test.", Line: "default", TTL: 300, Priority: &n}
	if _, err = p.ReplaceDNSRecord(ctx, "51", stale, next); err == nil {
		t.Fatal("accepted stale row")
	}
	bad := next
	bad.Type = "A"
	bad.Name = "other.example.test"
	bad.Content = "127.0.0.2"
	bad.Priority = nil
	if _, err = p.ReplaceDNSRecord(ctx, "51", prior, bad); err == nil {
		t.Fatal("overwrote existing record")
	}
	bad.Name = "outside.test"
	if _, err = p.ReplaceDNSRecord(ctx, "51", prior, bad); err == nil {
		t.Fatal("foreign name")
	}
	if updates != 0 {
		t.Fatal(updates)
	}
	if id, err := p.ReplaceDNSRecord(ctx, "51", prior, next); err != nil || id != "11" {
		t.Fatal(id, err)
	}
	pg, err = p.DNSRecords(ctx, "51", 1, next.Name)
	if err != nil || len(pg.Items) != 1 || *pg.Items[0].Priority != n {
		t.Fatal(pg, err)
	}
	next.Type = "TXT"
	next.Content = "changed"
	next.Priority = nil
	if id, err := p.ReplaceDNSRecord(ctx, "51", pg.Items[0], next); err != nil || id != "11" || updates != 2 {
		t.Fatal(id, err, updates)
	}
}
