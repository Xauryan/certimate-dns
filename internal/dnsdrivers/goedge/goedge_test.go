package goedge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestScopedRPC(t *testing.T) {
	ctx := context.Background()
	zone := `{"id":"10","name":"example.test","nsCluster":{"id":"12"},"userId":"8"}`
	rec := `{"id":"53","nsDomain":{"id":"10"},"name":"www","type":"MX","value":"mail.example.test","ttl":300,"isOn":true,"mxPriority":7,"weight":8,"description":"keep","nsRoutes":[{"code":"region:1"}]}`
	updates := 0
	tokens := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q map[string]any
		json.NewDecoder(r.Body).Decode(&q)
		if r.URL.Path != "/APIAccessTokenService/getAPIAccessToken" && r.Header.Get("X-Edge-Access-Token") != "synthetic-token" {
			t.Error("token missing")
		}
		var data string
		switch r.URL.Path {
		case "/APIAccessTokenService/getAPIAccessToken":
			tokens++
			if q["accessKey"] != "synthetic-key" || q["type"] != "admin" {
				t.Error("auth fields")
			}
			data = fmt.Sprintf(`{"token":"synthetic-token","expiresAt":"%d"}`, time.Now().Unix()+600)
		case "/NSDomainService/findNSDomain":
			data = `{"nsDomain":` + zone + `}`
		case "/NSRecordService/findNSRecord":
			data = `{"nsRecord":` + rec + `}`
		case "/NSRecordService/updateNSRecord":
			updates++
			if q["nsRecordId"] != float64(53) || q["value"] != "mx2.example.test" || q["ttl"] != float64(600) || q["isOn"] != true || q["mxPriority"] != float64(7) || q["weight"] != float64(8) || q["description"] != "keep" || q["nsRouteCodes"].([]any)[0] != "region:1" {
				t.Error("lost update fields")
			}
			data = "{}"
		case "/NSRecordService/createNSRecord":
			if q["nsDomainId"] != float64(10) || q["srvPriority"] != float64(4) || q["srvWeight"] != float64(8) || q["srvPort"] != float64(443) || q["value"] != "edge.example.test" || q["description"] != "create" {
				t.Error("invalid SRV payload")
			}
			data = `{"nsRecordId":"54"}`
		case "/NSDomainService/createNSDomain":
			if q["nsClusterId"] != float64(12) || q["userId"] != float64(8) || q["name"] != "test.example" {
				t.Error("unscoped zone creation")
			}
			data = `{"nsDomainId":"11"}`
		default:
			w.WriteHeader(400)
			fmt.Fprint(w, "synthetic-key")
			return
		}
		fmt.Fprintf(w, `{"code":200,"data":%s}`, data)
	}))
	defer srv.Close()
	api, err := New(&domain.Access{Config: map[string]any{"serverUrl": srv.URL, "apiRole": "admin", "accessKeyId": "synthetic-id", "accessKey": "synthetic-key", "nsClusterId": 12, "userId": "8", "allowInsecureConnections": true}})
	if err != nil {
		t.Fatal(err)
	}
	p := api.(*provider)
	if _, err = p.PatchDNSRecord(ctx, "10", "53", dns.RecordPatch{Content: "mx2.example.test", TTL: 600}); err != nil {
		t.Fatal(err)
	}
	id, err := p.CreateDNSRecord(ctx, "10", dns.RecordInput{Name: "_srv._tcp.example.test", Type: "SRV", Content: "4 8 443 edge.example.test", TTL: 60, Description: "create"})
	if err != nil || id != "54" {
		t.Fatal(id, err)
	}
	z, err := p.CreateZone(ctx, "test.example")
	if err != nil || z.ID != "11" {
		t.Fatal(z, err)
	}
	rec = strings.Replace(rec, `"id":"10"`, `"id":"11"`, 1)
	if _, err = p.DeleteDNSRecord(ctx, "10", "53"); err != domain.ErrRecordNotFound {
		t.Fatal("foreign record", err)
	}
	zone = strings.Replace(zone, `"id":"12"`, `"id":"13"`, 1)
	if _, err = p.PatchDNSRecord(ctx, "10", "53", dns.RecordPatch{Content: "other", TTL: 60}); err != domain.ErrRecordNotFound {
		t.Fatal("foreign cluster", err)
	}
	if tokens != 1 || updates != 1 {
		t.Fatal(tokens, updates)
	}
}

func TestNodeAddress(t *testing.T) {
	for _, tc := range []struct {
		url     string
		opt, ok bool
	}{
		{"https://node.example.test", false, true},
		{"http://localhost:8004", true, true}, {"http://127.0.0.1", false, false}, {"http://10.0.0.9", true, true},
		{"http://[::1]", true, true}, {"http://[fd00::10]", true, true}, {"http://node.example.test", true, false},
		{"https://node.example.test?key=synthetic", false, false}, {"https://user@node.example.test", false, false}, {"https://node.example.test#fragment", false, false},
	} {
		_, err := New(&domain.Access{Config: map[string]any{"serverUrl": tc.url, "allowInsecureConnections": tc.opt, "apiRole": "admin", "accessKey": "synthetic", "accessKeyId": "test", "nsClusterId": 1}})
		if (err == nil) != tc.ok {
			t.Errorf("config result for %s: %v", tc.url, err)
		}
	}
}
