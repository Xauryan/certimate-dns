package jdcloud

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

func TestJDCloudScopedOperations(t *testing.T) {
	if _, e := New(nil); e == nil {
		t.Fatal("accepted empty credentials")
	}
	raw, err := New(&domain.Access{Config: map[string]any{"accessKeyId": "test-id", "accessKeySecret": "test-key"}})
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*provider)
	const row = `{"id":11,"hostRecord":"@","hostValue":"example.test.","type":"SRV","ttl":600,"mxPriority":1,"weight":2,"port":443,"jcloudRes":true,"viewValue":[0,-1],"resolvingStatus":2}`
	records := `{"totalCount":1,"dataList":[` + row + `]}`
	writes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var result string
		if r.Header.Get("Authorization") == "" {
			t.Error("unsigned request")
		}
		if r.Method != "GET" {
			writes++
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /domain":
			z := "7"
			if r.URL.Query().Get("domainId") == "8" {
				z = "8"
			}
			result = fmt.Sprintf(`{"totalCount":1,"dataList":[{"id":%s,"domainName":"example.test","resolvingStatus":1,"packId":12}]}`, z)
		case "GET /domain/7/viewTree":
			if r.URL.Query().Get("packId") != "12" {
				t.Error("wrong pack")
			}
			result = `{"data":[{"label":"default","value":-1,"leaf":true}]}`
		case "GET /domain/7/ResourceRecord":
			result = records
		case "GET /domain/8/ResourceRecord":
			result = `{"totalCount":0,"dataList":[]}`
		case "POST /domain":
			var b struct {
				DomainName string
				PackId     *int
			}
			if e := json.NewDecoder(r.Body).Decode(&b); e != nil || b.DomainName != "example.test" || b.PackId == nil {
				t.Error("bad zone create")
			}
			result = `{"data":{"id":7,"domainName":"example.test"}}`
		case "POST /domain/7/ResourceRecord", "PUT /domain/7/ResourceRecord/11":
			var b struct {
				Req struct {
					HostRecord, DomainName, HostValue   string
					ViewValue, MxPriority, Weight, Port int
					JcloudRes                           bool
				}
			}
			if e := json.NewDecoder(r.Body).Decode(&b); e != nil {
				t.Error(e)
			}
			if b.Req.HostRecord != "@" || b.Req.MxPriority != 2 || b.Req.Weight != 3 || b.Req.Port != 443 || b.Req.HostValue != "server.test." || b.Req.ViewValue != -1 {
				t.Errorf("bad fields %+v", b.Req)
			}
			if r.Method == "PUT" && (!b.Req.JcloudRes || b.Req.DomainName != "example.test") {
				t.Error("lost metadata")
			}
			result = `{"dataList":{"id":11}}`
		case "PUT /domain/7/ResourceRecord/11/status":
			var b struct{ Action string }
			if e := json.NewDecoder(r.Body).Decode(&b); e != nil || b.Action != "disable" {
				t.Error("bad status body")
			}
			result = "{}"
		case "DELETE /domain/7/ResourceRecord/11":
			result = "{}"
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{"requestId":"test","result":%s}`, result)
	}))
	defer srv.Close()
	p.endpoint = srv.URL + "/domain"
	ctx := t.Context()
	z, err := p.Zones(ctx, 1)
	if err != nil || len(z.Items) != 1 {
		t.Fatal(z, err)
	}
	if _, err = p.CreateZone(ctx, "example.test."); err != nil {
		t.Fatal(err)
	}
	detail, err := p.ZoneDetails(ctx, "7")
	if err != nil || len(detail.Lines) != 1 {
		t.Fatal(detail, err)
	}
	record, err := p.DNSRecords(ctx, "7", 1, "")
	if err != nil || len(record.Items) != 1 || record.Items[0].Content != "1 2 443 example.test." || record.Items[0].Status != "enabled" {
		t.Fatal(record, err)
	}
	input := dns.RecordInput{Name: "example.test.", Type: "SRV", Content: "2 3 443 server.test.", TTL: 600, Line: "-1"}
	if _, err = p.CreateDNSRecord(ctx, "7", input); err != nil {
		t.Fatal(err)
	}
	if _, err = p.PatchDNSRecord(ctx, "7", "11", dns.RecordPatch{Content: input.Content, TTL: 600}); err != nil {
		t.Fatal(err)
	}
	if err = p.SetBatchAttribute(ctx, "7", "11", "status", "disabled"); err != nil {
		t.Fatal(err)
	}
	if _, err = p.DeleteDNSRecord(ctx, "7", "11"); err != nil {
		t.Fatal(err)
	}
	if _, err = p.DeleteDNSRecord(ctx, "8", "11"); err == nil {
		t.Fatal("cross-zone delete")
	}
	records = strings.Replace(records, `"totalCount":1`, `"totalCount":4`, 1)
	if _, err = p.DeleteDNSRecord(ctx, "7", "11"); err == nil {
		t.Fatal("partial inventory caused deletion")
	}
	if writes != 5 {
		t.Fatalf("writes=%d", writes)
	}
}

func TestJDURLAndMXWireValues(t *testing.T) {
	raw, err := New(&domain.Access{Config: map[string]any{"accessKeyId": "id", "accessKeySecret": "test"}})
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*provider)
	wireType := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := `{"totalCount":1,"dataList":[{"id":7,"domainName":"example.test"}]}`
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "ResourceRecord"):
			result = `{"totalCount":1,"dataList":[{"id":44,"hostRecord":"@","hostValue":"old.test.","type":"MX","ttl":600,"mxPriority":21,"viewValue":[-1],"resolvingStatus":"2"}]}`
		case r.Method == "POST" || r.Method == "PUT":
			var b struct {
				Req struct {
					Type, HostValue string
					MxPriority      *int
				}
			}
			if e := json.NewDecoder(r.Body).Decode(&b); e != nil {
				t.Error(e)
			}
			if b.Req.Type != wireType {
				t.Errorf("type %s, want %s", b.Req.Type, wireType)
			}
			if wireType == "MX" && (b.Req.MxPriority == nil || *b.Req.MxPriority != 21 || b.Req.HostValue != "new.test.") {
				t.Error("lost MX preference")
			}
			result = `{"dataList":{"id":44}}`
		}
		fmt.Fprintf(w, `{"requestId":"test","result":%s}`, result)
	}))
	defer srv.Close()
	p.endpoint = srv.URL + "/domain"
	for _, typ := range []struct{ alias, wire string }{{"REDIRECT_URL", "EXPLICIT_URL"}, {"FORWARD_URL", "IMPLICIT_URL"}, {"IMPLICIT_URL", "IMPLICIT_URL"}} {
		wireType = typ.wire
		if _, e := p.CreateDNSRecord(t.Context(), "7", dns.RecordInput{Name: "@", Type: typ.alias, Content: "https://example.test", TTL: 600}); e != nil {
			t.Fatal(e)
		}
	}
	wireType = "MX"
	rows, e := p.DNSRecords(t.Context(), "7", 1, "")
	if e != nil || len(rows.Items) != 1 || rows.Items[0].Content != "21 old.test." || rows.Items[0].Priority == nil || *rows.Items[0].Priority != 21 {
		t.Fatal(rows, e)
	}
	if _, e = p.PatchDNSRecord(t.Context(), "7", "44", dns.RecordPatch{Content: "new.test.", TTL: 600}); e != nil {
		t.Fatal(e)
	}
}
