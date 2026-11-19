package bt

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestScopedAtomicReplace(t *testing.T) {
	var writes int
	row := record{zoneKey: zoneKey{31, 2}, ID: 5, Host: "www", Type: "A", TTL: 600, Value: "127.0.0.1", MX: 1, ViewID: 2, Remark: "keep", State: 1}
	p := &provider{http: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		data := "{}"
		switch r.URL.Path {
		case "/api/v1/dns/record/list":
			raw, _ := json.Marshal(map[string]any{"count": 1, "data": []record{row}})
			data = string(raw)
		case "/api/v1/dns/manage/check_domain_status":
			data = `{"domain_id":31,"domain_type":2,"full_domain":"example.test"}`
		case "/api/v1/dns/record/update":
			writes++
			var q map[string]any
			json.NewDecoder(r.Body).Decode(&q)
			if len(q) != 10 || q["record_id"] != float64(5) || q["domain_id"] != float64(31) || q["record"] != "mail" || q["mx"] != float64(8) || q["type"] != "MX" || q["ttl"] != float64(300) || q["view_id"] != float64(2) || q["remark"] != "keep" {
				t.Error("unexpected changed fields", q)
			}
		default:
			t.Fatal("unexpected API request")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"code":0,"data":` + data + `}`))}, nil
	})}}
	prior := row.dns("example.test")
	priority := 8
	in := dns.RecordInput{Name: "mail.example.test", Type: "MX", Content: "mx.example.test", TTL: 300, Priority: &priority, Line: prior.Line, Description: prior.Description}
	id, err := p.ReplaceDNSRecord(context.Background(), "31|2", prior, in)
	if err != nil || id != "5" {
		t.Fatal(id, err)
	}
	in.Name = "outside.test"
	if _, err = p.ReplaceDNSRecord(context.Background(), "31|2", prior, in); err == nil {
		t.Fatal("out of zone owner")
	}
	in.Name = "mail.example.test"
	row.MX = 6
	prior = row.dns("example.test")
	in.Weight = prior.Weight
	if _, err = p.ReplaceDNSRecord(context.Background(), "31|2", prior, in); err == nil {
		t.Fatal("converted a record whose routing weight would be lost")
	}
	if writes != 1 {
		t.Fatal(writes)
	}
}
