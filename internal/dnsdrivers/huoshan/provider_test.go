package huoshan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestVolcengineScopedOperations(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("accepted empty credentials")
	}
	raw, err := New(&domain.Access{Config: map[string]any{"accessKeyId": "test-id", "secretAccessKey": "test-key", "projectName": "team"}})
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*provider)
	const zoneList = `{"Total":1,"Zones":[{"ZID":7,"ZoneName":"example.test","ProjectName":"team","Stage":0}]}`
	const rr = `{"RecordID":"r1","Host":"@","Line":"default","TTL":600,"Type":"A","Value":"10.0.0.1","Remark":"keep","Weight":3,"Enable":true}`
	records := `{"TotalCount":1,"Records":[` + rr + `]}`
	zones := zoneList
	writes := []string{}
	weight := 3
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		action := q.Get("Action")
		if !strings.HasPrefix(r.Header.Get("Authorization"), "HMAC-SHA256 ") || q.Get("Version") != "2018-08-01" {
			t.Error("bad signature or version")
		}
		var result string
		switch r.Method {
		case "GET":
			if q.Get("ProjectName") != "team" {
				t.Error("unscoped GET")
			}
			switch action {
			case "ListZones":
				result = zones
			case "ListRecords":
				if q.Get("ZID") != "7" {
					t.Error("wrong ZID")
				}
				result = records
			case "QueryZone":
				result = `{"ZoneName":"example.test","TradeCode":"free_inner","Stage":0,"AllocateDNSServerList":["ns.example.test"]}`
			case "ListLines":
				result = `{"TotalCount":1,"Lines":[{"Value":"telecom","Name":"CT","Level":1}]}`
			case "ListCustomLines":
				result = `{"TotalCount":1,"CustomerLines":[{"Line":"cust","NameCN":"Custom"}]}`
			default:
				t.Errorf("unexpected GET %s", action)
			}
		case "POST":
			writes = append(writes, action)
			var body map[string]any
			if e := json.NewDecoder(r.Body).Decode(&body); e != nil || body["ProjectName"] != "team" {
				t.Error("unscoped write")
			}
			switch action {
			case "CreateZone":
				if body["ZoneName"] != "example.test" {
					t.Error("wrong zone")
				}
				result = `{"ZID":7,"ZoneName":"example.test","ProjectName":"team"}`
			case "CreateRecord":
				if body["ZID"] != float64(7) || body["Host"] != "@" || body["Line"] != "default" || body["Weight"] != float64(3) || body["Remark"] != "keep" {
					t.Error("wrong create body")
				}
				result = rr
			case "UpdateRecord":
				if body["RecordID"] != "r1" || body["Weight"] != float64(3) || body["Host"] != "@" || body["Line"] != "default" || body["Remark"] != "keep" {
					t.Errorf("lost record metadata %v", body)
				}
				result = rr
			case "UpdateRecordStatus":
				if body["Enable"] != false || body["RecordID"] != "r1" {
					t.Error("bad status")
				}
				result = strings.Replace(rr, `"Enable":true`, `"Enable":false`, 1)
			case "DeleteRecord":
				if body["RecordID"] != "r1" {
					t.Error("wrong record")
				}
				result = "{}"
			default:
				t.Errorf("unexpected POST %s", action)
			}
		default:
			t.Error("unexpected HTTP method")
		}
		fmt.Fprintf(w, `{"ResponseMetadata":{"RequestId":"test"},"Result":%s}`, result)
	}))
	defer server.Close()
	p.endpoint = server.URL + "/"
	ctx := t.Context()
	list, err := p.Zones(ctx, 1)
	if err != nil || len(list.Items) != 1 {
		t.Fatal(list, err)
	}
	if _, err = p.CreateZone(ctx, "example.test"); err != nil {
		t.Fatal(err)
	}
	info, err := p.ZoneDetails(ctx, "example.test")
	if err != nil || info.MinTTL != 600 || len(info.Lines) != 3 {
		t.Fatal(info, err)
	}
	if _, err = p.CreateDNSRecord(ctx, "example.test", dns.RecordInput{Name: "@", Type: "A", Content: "10.0.0.1", TTL: 600, Description: "keep", Weight: &weight}); err != nil {
		t.Fatal(err)
	}
	rows, err := p.DNSRecords(ctx, "example.test", 1, "")
	if err != nil || len(rows.Items) != 1 || rows.Items[0].Description != "keep" {
		t.Fatal(rows, err)
	}
	if _, err = p.PatchDNSRecord(ctx, "example.test", "r1", dns.RecordPatch{Content: "10.0.0.2", TTL: 800}); err != nil {
		t.Fatal(err)
	}
	if err = p.SetBatchAttribute(ctx, "example.test", "r1", "status", "disabled"); err != nil {
		t.Fatal(err)
	}
	if _, err = p.DeleteDNSRecord(ctx, "example.test", "r1"); err != nil {
		t.Fatal(err)
	}
	if _, err = p.DeleteDNSRecord(ctx, "child.example.test", "r1"); err == nil {
		t.Fatal("cross-zone delete")
	}
	records = `{"TotalCount":2,"Records":[` + rr + "," + strings.Replace(rr, "r1", "sibling", 1) + `]}`
	if _, err = p.PatchDNSRecord(ctx, "example.test", "r1", dns.RecordPatch{Content: "10.0.0.2", TTL: 601}); err == nil {
		t.Fatal("changed sibling TTL")
	}
	records = `{"TotalCount":1,"Records":[` + rr + `]}`
	records = strings.Replace(records, `"TotalCount":1`, `"TotalCount":2`, 1)
	if _, err = p.DeleteDNSRecord(ctx, "example.test", "r1"); err == nil {
		t.Fatal("partial list caused delete")
	}
	zones = strings.Replace(zoneList, "team", "other-project", 1)
	if _, err = p.DeleteDNSRecord(ctx, "example.test", "r1"); err == nil {
		t.Fatal("cross project")
	}
	if len(writes) != 5 {
		t.Fatalf("writes %v", writes)
	}
}
