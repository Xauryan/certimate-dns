package spaceship

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestExactValueMutationAndPagination(t *testing.T) {
	items := []map[string]any{
		{"name": "@", "type": "TXT", "value": "Case-A", "ttl": 600, "group": map[string]string{"type": "custom"}},
		{"name": "@", "type": "TXT", "value": "case-a", "ttl": 600, "group": map[string]string{"type": "custom"}},
		{"name": "svc", "type": "CNAME", "cname": "edge.example.test.", "ttl": 600, "group": map[string]string{"type": "product"}},
	}
	for i := 3; i < 501; i++ {
		items = append(items, map[string]any{"name": fmt.Sprintf("node-%d", i), "type": "A", "address": "10.0.0.1", "ttl": 600, "group": map[string]string{"type": "custom"}})
	}
	incomplete := true
	writes := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "sample-key" || r.Header.Get("X-API-Secret") != "sample-secret" {
			t.Error("missing credentials")
		}
		if r.URL.Path == "/domains" {
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]string{{"name": "example.test", "status": "active"}}, "total": 1})
			return
		}
		if r.URL.Path != "/dns/records/example.test" {
			t.Error("wrong zone")
		}
		switch r.Method {
		case "GET":
			skip, _ := strconv.Atoi(r.URL.Query().Get("skip"))
			take, _ := strconv.Atoi(r.URL.Query().Get("take"))
			page := items[skip:min(skip+take, len(items))]
			if skip == 500 && incomplete {
				page = nil
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": page, "total": len(items)})
		case "PUT":
			var body struct {
				Force bool
				Items []map[string]any
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Force || len(body.Items) != 1 {
				t.Error("bad PUT")
				return
			}
			record := body.Items[0]
			if record["ttl"] != float64(600) || record["name"] != "@" {
				t.Error("wrong PUT identity or TTL")
			}
			if record["type"] == "MX" {
				if record["preference"] != float64(20) || record["exchange"] != "mx.example.test." {
					t.Error("invalid MX data")
				}
				writes = append(writes, "PUT MX")
			} else {
				writes = append(writes, "PUT "+record["value"].(string))
			}
			w.WriteHeader(204)
		case "DELETE":
			var body []map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 1 {
				t.Error("bad DELETE")
				return
			}
			if _, ok := body[0]["ttl"]; ok {
				t.Error("extraneous field in exact-value deletion")
			}
			writes = append(writes, "DELETE "+body[0]["value"].(string))
			w.WriteHeader(204)
		}
	}))
	defer server.Close()
	raw, err := New(&domain.Access{Config: map[string]any{"apiKey": "sample-key", "apiSecret": "sample-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*provider)
	p.api.Base = server.URL
	ctx := t.Context()
	zones, err := p.Zones(ctx, 1)
	if err != nil || zones.Items[0].ID != "example.test" {
		t.Fatalf("zones: %v", err)
	}
	page, err := p.DNSRecords(ctx, "example.test", 1, "")
	if err != nil || page.Info.Total != 501 || page.Items[0].ID == page.Items[1].ID || !page.Items[2].ReadOnly {
		t.Fatalf("records: %v", err)
	}
	req := dns.RecordPatch{Content: "updated", TTL: 600}
	_, err = p.PatchDNSRecord(ctx, "example.test", page.Items[0].ID, req)
	if err == nil || len(writes) != 0 {
		t.Fatal("wrote with incomplete second page")
	}
	incomplete = false
	if _, err := p.DeleteDNSRecord(ctx, "example.test", page.Items[2].ID); err == nil || len(writes) != 0 {
		t.Fatal("managed record deleted")
	}
	if _, err := p.PatchDNSRecord(ctx, "example.test", page.Items[0].ID, dns.RecordPatch{Content: "case-a", TTL: 600}); err == nil || len(writes) != 0 {
		t.Fatal("overwrote existing sibling")
	}
	if _, err := p.PatchDNSRecord(ctx, "example.test", page.Items[0].ID, req); err != nil {
		t.Fatal(err)
	}
	if _, err := p.DeleteDNSRecord(ctx, "example.test", page.Items[1].ID); err != nil {
		t.Fatal(err)
	}
	priority := 20
	if _, err := p.CreateDNSRecord(ctx, "example.test", dns.RecordInput{Name: "example.test", Type: "MX", Content: "mx.example.test.", Priority: &priority, TTL: 600}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(writes, "|") != "PUT updated|DELETE Case-A|DELETE case-a|PUT MX" {
		t.Fatalf("unexpected writes %v", writes)
	}
}

func TestTypedRecordRoundTrip(t *testing.T) {
	for typ, value := range map[string]string{"CAA": `0 issue "ca.example.test; allow=1"`, "SRV": "12 22 443 target.example.test.", "ALIAS": "target.example.test.", "PTR": "ptr.example.test."} {
		r, err := newRecord("@", typ, value)
		if err != nil || r.content() != value {
			t.Errorf("failed to round-trip %s: %v", typ, err)
		}
	}
}
