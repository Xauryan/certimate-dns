package cloudflare

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestAutomationNormalizesPausedOwnerAndPatchesAtomically(t *testing.T) {
	for _, tt := range []struct{ physical, logical string }{{"www_pause.example.test", "www.example.test"}, {"__root___pause.example.test", "example.test"}} {
		c := localClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			var result any
			switch {
			case r.Method == "GET" && r.URL.Path == "/zones/"+testZone:
				result = Zone{ID: testZone, Name: "example.test"}
			case r.Method == "GET" && r.URL.Path == "/zones/"+testZone+"/dns_records/"+testRecord:
				result = DNSRecord{ID: testRecord, Name: tt.physical, Type: "A", Content: "10.0.0.8", TTL: 300}
			case r.Method == "PATCH" && r.URL.Path == "/zones/"+testZone+"/dns_records/"+testRecord:
				var b map[string]any
				if err := json.NewDecoder(r.Body).Decode(&b); err != nil || len(b) != 3 || b["ttl"] != float64(1) || b["proxied"] != true || b["content"] != "10.0.0.9" {
					t.Error("unexpected atomic patch", b, err)
				}
				result = DNSRecord{ID: testRecord}
			default:
				t.Fatal("unexpected path", r.URL.Path)
			}
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
		})
		r, err := c.AutomationRecord(context.Background(), testZone, testRecord)
		if err != nil || r.Name != tt.logical || r.Status != "disabled" {
			t.Fatal(r, err)
		}
		id, err := c.PatchDNSRecordProxy(context.Background(), testZone, testRecord, RecordPatch{TTL: 1, Content: "10.0.0.9"}, true)
		if err != nil || id != testRecord {
			t.Fatal(id, err)
		}
	}
}
