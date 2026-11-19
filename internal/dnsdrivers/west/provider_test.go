package west

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestRecordScopeAndSignedForms(t *testing.T) {
	complete := false
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		q := r.PostForm
		if r.Method != "POST" || q.Get("username") != "sample-user" || q.Get("token") != fmt.Sprintf("%x", md5.Sum([]byte("sample-usersample-pass"+q.Get("time")))) {
			t.Error("invalid signature")
		}
		answer := func(data any) { _ = json.NewEncoder(w).Encode(map[string]any{"result": "200", "data": data}) }
		if q.Get("act") != "getdomains" && q.Get("domain") != "example.test" {
			t.Error("missing zone")
		}
		switch q.Get("act") {
		case "getdomains":
			answer(map[string]any{"items": []map[string]string{{"domain": "example.test"}}, "total": "1"})
		case "getdnsrecord":
			rows := []map[string]any{}
			if q.Get("pageno") == "1" {
				for i := 1; i <= dns.DNSPageSize; i++ {
					rows = append(rows, map[string]any{"id": i, "type": "MX", "item": "@", "value": "mx.example.test", "ttl": 600, "level": 10, "line": "LTEL", "pause": 0})
				}
			} else if complete {
				rows = append(rows, map[string]any{"id": 21, "type": "A", "item": "www", "value": "10.0.0.8", "ttl": 600, "pause": 0})
			}
			answer(map[string]any{"total": 21, "items": rows})
		case "moddnsrecord":
			if q.Get("id") != "1" || q.Get("line") != "LTEL" || q.Get("value") != "mx2.example.test" || q.Get("level") != "42" {
				t.Error("incorrect update form")
			}
			writes++
			answer(nil)
		case "adddnsrecord":
			if q.Get("host") != "*" || q.Get("line") != "" {
				t.Error("incorrect add form")
			}
			writes++
			answer(map[string]any{"id": "33"})
		case "deldnsrecord":
			if q.Get("id") != "21" {
				t.Error("incorrect delete ID")
			}
			writes++
			answer(nil)
		case "pause":
			if q.Get("val") != "1" || q.Get("id") != "21" {
				t.Error("incorrect pause")
			}
			writes++
			answer(nil)
		default:
			t.Errorf("unknown act %s", q.Get("act"))
		}
	}))
	defer server.Close()
	raw, err := New(&domain.Access{Config: map[string]any{"username": "sample-user", "apiPassword": "sample-pass"}})
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*provider)
	p.endpoint = server.URL
	ctx := t.Context()
	if zones, err := p.Zones(ctx, 1); err != nil || len(zones.Items) != 1 {
		t.Fatalf("zones: %v", err)
	}
	req := dns.RecordPatch{Content: "42 mx2.example.test", TTL: 3600}
	if _, err := p.PatchDNSRecord(ctx, "example.test", "1", req); err == nil || writes != 0 {
		t.Fatal("updated after incomplete second page")
	}
	complete = true
	if _, err := p.PatchDNSRecord(ctx, "example.test", "1", req); err != nil {
		t.Fatal(err)
	}
	id, err := p.CreateDNSRecord(ctx, "example.test", dns.RecordInput{Type: "A", Content: "10.0.0.1", Name: "*.example.test", Line: "default", TTL: 60})
	if err != nil || id != "33" {
		t.Fatalf("create: %v", err)
	}
	if _, err := p.DeleteDNSRecord(ctx, "example.test", "42"); err == nil || writes != 2 {
		t.Fatal("deleted foreign ID")
	}
	if err := p.SetBatchAttribute(ctx, "example.test", "21", "status", "disabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.DeleteDNSRecord(ctx, "example.test", "21"); err != nil || writes != 4 {
		t.Fatalf("delete: %v", err)
	}
}
