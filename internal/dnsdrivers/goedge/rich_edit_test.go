package goedge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	u "github.com/certimate-go/certimate/internal/dnsdrivers/selfhostutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestReplaceRetainsRoutesAndStatus(t *testing.T) {
	writes := 0
	row := nsRecord{recordData: recordData{Name: "www", Type: "CAA", TTL: 600, Value: "acme.test", CAAFlag: 1, CAATag: "issue", Weight: 7, Description: "keep"}, ID: "22", NSRoutes: []route{{Code: "custom"}}, NSDomain: &scopeID{ID: "7"}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data any
		switch r.URL.Path {
		case "/NSDomainService/findNSDomain":
			data = map[string]any{"nsDomain": map[string]any{"id": 7, "name": "example.test", "nsCluster": map[string]int{"id": 1}}}
		case "/NSRecordService/findNSRecord":
			data = map[string]any{"nsRecord": row}
		case "/NSRecordService/updateNSRecord":
			writes++
			var q map[string]any
			json.NewDecoder(r.Body).Decode(&q)
			if q["name"] != "mail" || q["type"] != "MX" || q["mxPriority"] != float64(9) || q["isOn"] != false || q["description"] != "keep" || q["weight"] != float64(7) || q["nsRouteCodes"].([]any)[0] != "custom" || q["caaTag"] != "" {
				t.Error("replacement", q)
			}
		default:
			t.Error("unexpected call", r.URL.Path)
		}
		raw, _ := json.Marshal(data)
		fmt.Fprintf(w, `{"code":200,"data":%s}`, raw)
	}))
	defer server.Close()
	rpc, _ := u.NewClient(server.URL)
	p := &provider{rpc: rpc, clusterID: 1, token: "synthetic", validUntil: time.Now().Add(time.Hour)}
	prior := row.dns("example.test")
	priority := 9
	in := dns.RecordInput{Name: "mail.example.test", Type: "MX", Content: "mx.example.test", TTL: 600, Priority: &priority, Line: prior.Line, Description: prior.Description, Weight: prior.Weight}
	id, err := p.ReplaceDNSRecord(context.Background(), "7", prior, in)
	if err != nil || id != "22" {
		t.Fatal(id, err)
	}
	row.TTL = 61
	if _, err = p.ReplaceDNSRecord(context.Background(), "7", prior, in); err == nil {
		t.Fatal("stale record")
	}
	if writes != 1 {
		t.Fatal(writes)
	}
}
