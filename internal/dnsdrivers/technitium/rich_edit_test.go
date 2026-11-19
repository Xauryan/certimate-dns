package technitium

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestRichUpdateUsesOldAndNewOwnerAndPreference(t *testing.T) {
	zone := "example.test"
	owner := "mail.example.test"
	dest := "moved.example.test"
	makeRecord := func(name, v string, n int) map[string]any {
		return map[string]any{"name": name, "type": "MX", "ttl": 300, "comments": "retain", "expiryTtl": 800, "disabled": true, "rData": map[string]any{"exchange": v, "preference": n}}
	}
	old := makeRecord(owner, "old.example.test.", 10)
	sibling := makeRecord(dest, "occupied.example.test.", 25)
	var updates int
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("zone") != zone {
			t.Error("wrong zone")
		}
		resp := map[string]any{"zone": map[string]string{"name": zone, "type": "Primary"}}
		switch r.URL.Path {
		case "/api/zones/records/get":
			resp["records"] = []any{old, sibling}
		case "/api/zones/records/update":
			updates++
			want := map[string]string{"domain": owner, "type": "MX", "exchange": "old.example.test.", "preference": "10", "newDomain": dest, "newExchange": "new.example.test.", "newPreference": "20", "ttl": "600", "comments": "retain", "expiryTtl": "800", "disable": "true"}
			for k, v := range want {
				if r.FormValue(k) != v {
					t.Errorf("field %s mismatch", k)
				}
			}
			old = makeRecord(dest, "new.example.test.", 20)
			old["ttl"] = 600
			resp["updatedRecord"] = old
		default:
			t.Errorf("unexpected operation %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "response": resp})
	}))
	defer s.Close()
	api, err := New(&domain.Access{Config: map[string]any{"serverUrl": s.URL, "apiToken": "fixture-token"}})
	if err != nil {
		t.Fatal(err)
	}
	p := api.(*provider)
	ctx := context.Background()
	rows, err := p.DNSRecords(ctx, zone, 1, owner)
	if err != nil {
		t.Fatal(err)
	}
	prior := rows.Items[0]
	n := 20
	desired := dns.RecordInput{Name: dest, Type: "MX", Content: "new.example.test.", TTL: 600, Priority: &n, Line: "default", Description: "retain"}
	stale := prior
	stale.TTL = 500
	if _, err = p.ReplaceDNSRecord(ctx, zone, stale, desired); err == nil {
		t.Fatal("accepted stale metadata")
	}
	bad := desired
	bad.Type = "A"
	if _, err = p.ReplaceDNSRecord(ctx, zone, prior, bad); err == nil {
		t.Fatal("accepted retype")
	}
	bad = desired
	bad.Content = "OCCUPIED.example.test"
	q := 25
	bad.Priority = &q
	if _, err = p.ReplaceDNSRecord(ctx, zone, prior, bad); err == nil {
		t.Fatal("accepted duplicate sibling")
	}
	bad = desired
	bad.Name = "outside.test"
	if _, err = p.ReplaceDNSRecord(ctx, zone, prior, bad); err == nil || updates != 0 {
		t.Fatal("wrote foreign name")
	}
	id, err := p.ReplaceDNSRecord(ctx, zone, prior, desired)
	if err != nil || id == prior.ID || updates != 1 {
		t.Fatal(id, err, updates)
	}
	rows, err = p.DNSRecords(ctx, zone, 1, dest)
	if err != nil || len(rows.Items) != 2 || rows.Items[0].ID != id || *rows.Items[0].Priority != n {
		t.Fatal(rows, err)
	}
}
