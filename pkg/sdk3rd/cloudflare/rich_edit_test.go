package cloudflare

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestCloudflareReplaceUsesScopedPartialPatch(t *testing.T) {
	ctx := context.Background()
	writes := 0
	prior := DNSRecord{ID: testRecord, Name: "old_pause.example.test", Type: "A", Content: "127.0.0.1", TTL: 600, Status: "disabled", Description: "keep", Line: "0"}
	c := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/zones/"+testZone+"/dns_records/"+testRecord {
			t.Fatal("unexpected detail scope")
		}
		switch r.Method {
		case "GET":
			io.WriteString(w, `{"success":true,"result":{"id":"`+testRecord+`","zone_name":"example.test","type":"A","name":"old_pause.example.test","content":"127.0.0.1","ttl":600,"proxied":false,"comment":"keep","tags":["team:a"]}}`)
		case "PATCH":
			var b map[string]any
			if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
				t.Fatal(err)
			}
			if b["type"] != "MX" || b["name"] != "new_pause.example.test" || b["priority"] != float64(12) || b["ttl"] != float64(300) || b["content"] != "mx.example.test" || len(b) != 5 {
				t.Error("edit would overwrite unrelated fields")
			}
			writes++
			io.WriteString(w, `{"success":true,"result":{"id":"`+testRecord+`"}}`)
		default:
			t.Fatal("non-atomic edit")
		}
	})
	priority := 12
	desired := RecordInput{Name: "new_pause.example.test", Type: "MX", Content: "mx.example.test", TTL: 300, Priority: &priority, Description: prior.Description, Line: prior.Line}
	if _, err := c.ReplaceDNSRecord(ctx, testZone, prior, desired); err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"other.example.test", "other_pause.example.org"} {
		desired.Name = owner
		if _, err := c.ReplaceDNSRecord(ctx, testZone, prior, desired); err == nil {
			t.Fatal("unexpected rename")
		}
	}
	desired.Name = "new_pause.example.test"
	prior.TTL++
	if _, err := c.ReplaceDNSRecord(ctx, testZone, prior, desired); err == nil || writes != 1 {
		t.Fatal("wrote after stale read")
	}
}

func TestCloudflareReplaceRejectsProxiedToNonProxiable(t *testing.T) {
	c := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Fatal("silently removed proxy on retype")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"success":true,"result":{"id":"`+testRecord+`","name":"www.example.test","type":"A","content":"127.0.0.1","ttl":1,"proxied":true}}`)
	})
	prior := DNSRecord{ID: testRecord, Name: "www.example.test", Type: "A", Content: "127.0.0.1", TTL: 1, Proxied: true, Line: "1"}
	_, err := c.ReplaceDNSRecord(context.Background(), testZone, prior, RecordInput{Name: prior.Name, Type: "TXT", Content: "value", TTL: 300, Line: prior.Line})
	if err == nil {
		t.Fatal("retyped proxied record")
	}
}
