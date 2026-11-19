package dynv6

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestZoneAndRecordLifecycle(t *testing.T) {
	const zone = "example.test"
	zoneID := 42
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sample-token" {
			t.Error("missing token")
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /zones":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 42, "name": zone}})
		case "GET /zones/by-name/example.test":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 42, "name": zone})
		case "GET /zones/42/records", "GET /zones/42/records/7":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 7, "zoneID": zoneID, "name": "mail.example.test", "type": "MX", "priority": 9, "data": "mx.example.test."})
		case "POST /zones/42/records":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["type"] != "MX" || body["name"] != zone || body["priority"] != float64(10) || body["data"] != "mx.example.test." {
				t.Error("incorrect create")
			}
			writes++
			_ = json.NewEncoder(w).Encode(map[string]int{"id": 9})
		case "PATCH /zones/42/records/7":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 2 || body["data"] != "new.example.test." || body["priority"] != float64(9) {
				t.Error("incorrect patch")
			}
			writes++
			w.WriteHeader(204)
		case "DELETE /zones/42/records/7":
			writes++
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected call %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	raw, err := New(&domain.Access{Config: map[string]any{"httpToken": "sample-token"}})
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*provider)
	p.api.Base = server.URL
	ctx := t.Context()
	zones, err := p.Zones(ctx, 1)
	if err != nil || len(zones.Items) != 1 || zones.Items[0].ID != zone {
		t.Fatalf("zones: %v", err)
	}
	page, err := p.DNSRecords(ctx, zone, 1, "mail")
	if err != nil || len(page.Items) != 1 || page.Items[0].Content != "9 mx.example.test." || page.Items[0].TTL != 600 {
		t.Fatalf("single-object response: %v", err)
	}
	priority := 10
	if id, err := p.CreateDNSRecord(ctx, zone, dns.RecordInput{Name: "@", Type: "MX", TTL: 600, Content: "mx.example.test", Priority: &priority}); err != nil || id != "9" {
		t.Fatalf("create: %v", err)
	}
	zoneID = 24
	if _, err := p.DeleteDNSRecord(ctx, zone, "7"); err == nil || writes != 1 {
		t.Fatal("foreign-zone delete")
	}
	zoneID = 0
	if _, err := p.DeleteDNSRecord(ctx, zone, "7"); err == nil || writes != 1 {
		t.Fatal("delete without provider zone ID")
	}
	zoneID = 42
	if _, err := p.PatchDNSRecord(ctx, zone, "7", dns.RecordPatch{TTL: 300, Content: "5 new.example.test"}); err == nil || writes != 1 {
		t.Fatal("ignored fixed TTL")
	}
	if _, err := p.PatchDNSRecord(ctx, zone, "7", dns.RecordPatch{TTL: 600, Content: "new.example.test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.DeleteDNSRecord(ctx, zone, "7"); err != nil || writes != 3 {
		t.Fatalf("delete: %v", err)
	}
}
