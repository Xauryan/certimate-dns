package dnsla

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	u "github.com/certimate-go/certimate/internal/dnsdrivers/selfhostutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestScopedRecordsAndZoneCreate(t *testing.T) {
	const zoneID = "83377004311234567"
	const targetID = "99477112233445567"
	row := record{ID: targetID, DomainID: zoneID, Type: 1, Host: "www", Data: "10.0.0.8", Line: "84455667788776655", TTL: 300, Disabled: true, Remark: "keep"}
	weight := 10
	row.Weight = &weight
	complete := true
	pageCalls, writes := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, pass, ok := r.BasicAuth(); !ok || user != "sample-id" || pass != "sample-secret" {
			t.Error("unexpected credentials")
		}
		answer := func(data any) {
			if err := json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": data}); err != nil {
				t.Error(err)
			}
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/domain":
			if r.URL.Query().Get("id") != zoneID {
				t.Error("wrong zone")
			}
			answer(map[string]any{"id": zoneID, "displayDomain": "example.test."})
		case "GET /api/domainList":
			answer(map[string]any{"results": []zone{{ID: zoneID, DisplayDomain: "example.test."}}, "total": 1})
		case "GET /api/recordList":
			pageCalls++
			if r.URL.Query().Get("domainId") != zoneID {
				t.Error("missing zone filter")
			}
			if r.URL.Query().Get("pageIndex") == "1" {
				items := []record{row}
				for i := 1; i < dns.DNSPageSize; i++ {
					sibling := row
					sibling.ID = u.Text(fmt.Sprint(i))
					items = append(items, sibling)
				}
				answer(map[string]any{"results": items, "total": dns.DNSPageSize + 1})
			} else if !complete {
				w.WriteHeader(http.StatusBadGateway)
			} else {
				sibling := row
				sibling.ID = "55"
				answer(map[string]any{"results": []record{sibling}, "total": dns.DNSPageSize + 1})
			}
		case "POST /api/domain":
			var b map[string]string
			if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b["domain"] != "example.test" {
				t.Error("bad create zone")
			}
			writes++
			answer(map[string]string{"id": zoneID})
		case "POST /api/record":
			var body record
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Line != row.Line || body.Type != 15 || body.DomainID != zoneID || body.Host != "mail" || body.Preference == nil || *body.Preference != 13 || body.Weight == nil || *body.Weight != 10 {
				t.Error("record create lost MX priority, weight, zone, owner or line")
			}
			writes++
			answer(map[string]string{"id": targetID})
		case "PUT /api/record":
			var body record
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID != targetID || body.Line != row.Line || body.DomainID != "" || body.Data != "10.0.0.9" || body.Weight == nil || *body.Weight != 10 || !body.Disabled || body.Remark != "keep" {
				t.Error("patch changed unrelated attributes")
			}
			writes++
			answer(nil)
		case "DELETE /api/record":
			if r.URL.Query().Get("id") != targetID {
				t.Error("bad delete ID")
			}
			writes++
			answer(nil)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	raw, err := New(&domain.Access{Config: map[string]any{"apiId": "sample-id", "apiSecret": "sample-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*provider)
	p.client.Base = server.URL
	ctx := t.Context()
	zonePage, err := p.Zones(ctx, 1)
	if err != nil || len(zonePage.Items) != 1 || zonePage.Items[0].ID != zoneID {
		t.Fatalf("list zones: %v", err)
	}
	zone, err := p.CreateZone(ctx, "Example.Test.")
	if err != nil || zone.ID != zoneID {
		t.Fatalf("create zone: %v", err)
	}
	priority := 13
	id, err := p.CreateDNSRecord(ctx, zoneID, dns.RecordInput{Name: "mail.example.test", Type: "MX", Priority: &priority, Weight: &weight, Content: "mx.example.test.", TTL: 300, Line: string(row.Line)})
	if err != nil || id != targetID {
		t.Fatalf("create: %v", err)
	}
	if _, err := p.PatchDNSRecord(ctx, zoneID, id, dns.RecordPatch{TTL: 600, Content: "10.0.0.9"}); err != nil {
		t.Fatal(err)
	}
	if pageCalls != 2 {
		t.Fatal("write preceded full inventory")
	}
	complete = false
	if _, err := p.DeleteDNSRecord(ctx, zoneID, id); err == nil || writes != 3 {
		t.Fatal("wrote after partial read")
	}
	complete = true
	if _, err := p.DeleteDNSRecord(ctx, zoneID, "foreign"); err == nil || writes != 3 {
		t.Fatal("deleted a foreign record")
	}
	if _, err := p.DeleteDNSRecord(ctx, zoneID, id); err != nil || writes != 4 {
		t.Fatalf("delete: %v", err)
	}
}
