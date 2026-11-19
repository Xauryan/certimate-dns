package huawei

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHuaweiZoneScopeAndRecordSetChanges(t *testing.T) {
	ctx := t.Context()
	const zoneData = `{"id":"zone","zone_type":"public","enterprise_project_id":"project","name":"example.test.","status":"ACTIVE"}`
	const recordData = `{"id":"one","type":"A","default":false,"name":"www.example.test.","zone_id":"zone","zone_name":"example.test.","line":"Dianxin","records":["10.0.0.1","10.0.0.2"],"status":"ACTIVE","weight":8,"description":"keep","ttl":600}`
	row := recordData
	projectZone := zoneData
	desired := []string{}
	writes := 0
	raw, err := New(&domain.Access{Config: map[string]any{"accessKeyId": "test-id", "secretAccessKey": "test-key", "enterpriseProjectId": "project"}})
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*provider)
	p.client.Transport = transport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") == "" {
			t.Error(" unsigned request")
		}
		var result string
		code := 200
		switch r.Method + " " + r.URL.Path {
		case "GET /v2/zones/zone":
			result = projectZone
		case "GET /v2/zones":
			if r.URL.Query().Get("enterprise_project_id") != "project" || r.URL.Query().Get("offset") != "0" {
				t.Error("missing project scope/paging")
			}
			result = fmt.Sprintf(`{"zones":[%s],"metadata":{"total_count":1}}`, projectZone)
		case "GET /v2.1/zones/zone/lines":
			result = `{"lines":[{"line":"Dianxin","line_name":"carrier"}],"metadata":{"total_count":1}}`
		case "GET /v2.1/zones/zone/recordsets/one":
			result = row
		case "GET /v2.1/zones/zone/recordsets":
			result = fmt.Sprintf(`{"recordsets":[%s],"metadata":{"total_count":1}}`, row)
		case "PUT /v2.1/zones/zone/recordsets/one", "POST /v2.1/zones/zone/recordsets":
			var data struct {
				Name, Type  string
				Records     []string
				TTL         int
				Weight      *int
				Description *string
			}
			if err := json.NewDecoder(r.Body).Decode(&data); err != nil || data.Name != "www.example.test." || data.TTL != 600 || !reflect.DeepEqual(data.Records, desired) || data.Weight != nil || data.Description != nil {
				t.Errorf("unexpected RRset write %+v", data)
			}
			writes++
			result = row
		default:
			code = 401
			result = "upstream reflected synthetic-secret"
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(result)), Header: make(http.Header)}, nil
	})
	z, err := p.Zones(ctx, 1)
	if err != nil || z.Info.Total != 1 {
		t.Fatal(z, err)
	}
	info, err := p.ZoneDetails(ctx, "zone")
	if err != nil || len(info.Lines) != 1 {
		t.Fatal(info, err)
	}
	list, err := p.DNSRecords(ctx, "zone", 1, "")
	if err != nil || len(list.Items) != 1 || list.Items[0].ReadOnly || list.Items[0].Content != "10.0.0.1\n10.0.0.2" {
		t.Fatal(list, err)
	}
	if _, err = p.PatchDNSRecord(ctx, "zone", "one", dns.RecordPatch{TTL: 600, Content: "10.0.0.3"}); err == nil {
		t.Fatal("ambiguous overwrite")
	}
	if _, err = p.DeleteDNSRecord(ctx, "zone", "one"); err == nil {
		t.Fatal("removed sibling")
	}
	desired = []string{"10.0.0.3", "10.0.0.2"}
	if _, err = p.PatchDNSRecord(ctx, "zone", "one", dns.RecordPatch{TTL: 600, Content: strings.Join(desired, "\n")}); err != nil {
		t.Fatal(err)
	}
	input := dns.RecordInput{Name: "www.example.test", Type: "A", TTL: 600, Line: "Dianxin"}
	desired = []string{"10.0.0.8", "10.0.0.9"}
	if _, err = p.SetRankedAddresses(ctx, "zone", "one", input, desired); err != nil {
		t.Fatal(err)
	}
	if _, err = p.SetRankedAddresses(ctx, "zone", "", input, desired); err != nil {
		t.Fatal(err)
	}
	row = strings.Replace(row, `"zone_id":"zone"`, `"zone_id":"other"`, 1)
	if _, err = p.SetRankedAddresses(ctx, "zone", "one", input, desired); err == nil {
		t.Fatal("cross-zone update")
	}
	row = strings.Replace(recordData, `"default":false`, `"default":true`, 1)
	if _, err = p.SetRankedAddresses(ctx, "zone", "one", input, desired); err == nil {
		t.Fatal("protected RRset write")
	}
	projectZone = strings.Replace(zoneData, `:"project"`, `:"other"`, 1)
	if _, err = p.SetRankedAddresses(ctx, "zone", "", input, desired); err == nil {
		t.Fatal("wrong project")
	}
	if _, err = p.DNSRecords(ctx, "missing", 1, ""); err == nil || strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatal("provider error leaked")
	}
	if writes != 3 {
		t.Fatalf("writes %d", writes)
	}
}
