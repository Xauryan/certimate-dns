package technitium

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestScopedRecordSetAndMetadata(t *testing.T) {
	row := func(value string) map[string]any {
		return map[string]any{"name": "www.example.test", "type": "A", "ttl": 300, "disabled": true, "comments": "keep note", "expiryTtl": 900, "rData": map[string]string{"ipAddress": value}}
	}
	records := []map[string]any{row("127.0.0.1"), row("127.0.0.2")}
	var writes []url.Values
	var overrideZone string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.RawQuery != "" || r.FormValue("token") != "fixture-token" {
			t.Error("token transport")
		}
		z := r.FormValue("zone")
		zone := map[string]any{"name": z, "type": "Primary", "disabled": false}
		reply := map[string]any{"status": "ok"}
		fail := false
		switch r.URL.Path {
		case "/proxy/api/zones/create":
			reply["response"] = map[string]string{"domain": z}
		case "/proxy/api/zones/list":
			reply["response"] = map[string]any{"zones": []any{map[string]string{"name": "example.test"}}}
		case "/proxy/api/zones/records/get":
			if overrideZone != "" {
				zone["name"] = overrideZone
			}
			if r.FormValue("listZone") != "true" || r.FormValue("domain") != z {
				t.Error("zone not explicit")
			}
			reply["response"] = map[string]any{"zone": zone, "records": records}
		case "/proxy/api/zones/records/update", "/proxy/api/zones/records/add":
			writes = append(writes, r.PostForm)
			val := r.FormValue("newIpAddress")
			if val == "" {
				val = r.FormValue("ipAddress")
			}
			k := "updatedRecord"
			if strings.HasSuffix(r.URL.Path, "add") {
				k = "addedRecord"
			}
			if val == "provider-failure" {
				fail = true
			}
			reply["response"] = map[string]any{"zone": zone, k: row(val)}
		case "/proxy/api/zones/records/delete":
			writes = append(writes, r.PostForm)
		default:
			t.Errorf("unexpected route %q", r.URL.Path)
		}
		if fail {
			fmt.Fprint(w, `{"status":"error","errorMessage":"fixture-token"}`)
			return
		}
		_ = json.NewEncoder(w).Encode(reply)
	}))
	defer s.Close()
	p0, err := New(&domain.Access{Config: map[string]any{"serverUrl": s.URL + "/proxy/", "apiToken": "fixture-token"}})
	if err != nil {
		t.Fatal(err)
	}
	p := p0.(*provider)
	ctx := context.Background()
	zones, err := p.Zones(ctx, 1)
	if err != nil || zones.Info.Total != 1 {
		t.Fatal(zones, err)
	}
	if _, err = p.CreateZone(ctx, "new.example.test"); err != nil {
		t.Fatal(err)
	}
	rows, err := p.DNSRecords(ctx, "example.test", 1, "www.example.test")
	if err != nil || len(rows.Items) != 2 {
		t.Fatal(rows, err)
	}
	id := rows.Items[0].ID
	slices.Reverse(records)
	newID, err := p.PatchDNSRecord(ctx, "example.test", id, dns.RecordPatch{TTL: 600, Content: "127.0.0.3"})
	if err != nil || newID == id {
		t.Fatal(newID, err)
	}
	if f := writes[0]; f.Get("ipAddress") != "127.0.0.1" || f.Get("newIpAddress") != "127.0.0.3" || f.Get("disable") != "true" || f.Get("comments") != "keep note" || f.Get("expiryTtl") != "900" {
		t.Fatal("lost selector or metadata")
	}
	if err = p.SetBatchAttribute(ctx, "example.test", id, "remark", "new note"); err != nil || writes[1].Get("comments") != "new note" || writes[1].Get("disable") != "true" {
		t.Fatal(err)
	}
	if _, err = p.SetDNSRecordStatus(ctx, "example.test", id, true); err != nil || writes[2].Get("comments") != "keep note" || writes[2].Get("disable") != "false" {
		t.Fatal(err)
	}
	if _, err = p.DeleteDNSRecord(ctx, "example.test", id); err != nil || writes[3].Get("ipAddress") != "127.0.0.1" {
		t.Fatal(err)
	}
	if _, err = p.CreateDNSRecord(ctx, "example.test", dns.RecordInput{Name: "www.example.test", Type: "A", Content: "127.0.0.4", TTL: 600, Description: "note"}); err != nil || writes[4].Get("overwrite") != "false" || writes[4].Get("comments") != "note" {
		t.Fatal(err)
	}
	overrideZone = "other.test"
	if _, err = p.DeleteDNSRecord(ctx, "example.test", id); err == nil || len(writes) != 5 {
		t.Fatal("accepted mismatched zone")
	}
	overrideZone = ""
	records = append(records, map[string]any{"name": "foreign.test", "type": "TXT", "ttl": 300})
	if _, err = p.DeleteDNSRecord(ctx, "example.test", id); err == nil || len(writes) != 5 {
		t.Fatal("partial response write")
	}
	if _, err = p.CreateDNSRecord(ctx, "example.test", dns.RecordInput{Name: "www.example.test", Type: "A", Content: "127.0.0.4", TTL: 600}); err == nil || len(writes) != 5 {
		t.Fatal("partial response create")
	}
	records = records[:2]
	_, err = p.CreateDNSRecord(ctx, "example.test", dns.RecordInput{Type: "A", Name: "www.example.test", TTL: 600, Content: "provider-failure"})
	if err == nil || strings.Contains(err.Error(), "fixture-token") {
		t.Fatal("leaked provider reply")
	}
}

func TestAccountTransportSurvivesTLSOverride(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host != "dns.example.test" {
			t.Error("expected absolute proxy request")
		}
		fmt.Fprint(w, `{"status":"ok","response":{"zones":[]}}`)
	}))
	defer server.Close()
	proxy, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyURL(proxy)
	tr.TLSClientConfig = &tls.Config{ServerName: "dns.example.test"}
	api, err := New(&domain.Access{Config: map[string]any{"serverUrl": "http://dns.example.test", "apiToken": "fixture-token", "allowInsecureConnections": true}, DNSManagementTransport: tr})
	if err != nil {
		t.Fatal(err)
	}
	used := api.(*provider).client.HTTP.Transport.(*http.Transport)
	if used == tr || !used.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.InsecureSkipVerify || used.TLSClientConfig.ServerName != tr.TLSClientConfig.ServerName {
		t.Fatal("TLS override must be private to the account client")
	}
	if _, err = api.Zones(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
}
