package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testZone = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testRecord = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func localClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	c, err := NewClient(WithApiToken("synthetic-token"))
	if err != nil {
		t.Fatal(err)
	}
	c.rc.SetBaseURL(server.URL)
	return c
}

func TestDNSList(t *testing.T) {
	for _, zones := range []bool{true, false} {
		c := localClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer synthetic-token" || r.URL.Query().Get("page") != "2" || r.URL.Query().Get("per_page") != "20" {
				t.Error("unexpected authenticated page request")
			}
			want := "/zones"
			if !zones {
				want += "/" + testZone + "/dns_records"
				if r.URL.Query().Get("name.contains") != "_acme-challenge" {
					t.Error("missing provider-side name filter")
				}
			}
			if r.URL.Path != want {
				t.Errorf("unexpected route %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"success":true,"result":[{"name":"example.org"}],"result_info":{"page":2,"total_count":21}}`)
		})
		if zones {
			p, err := c.Zones(context.Background(), 2)
			if err != nil || p.Info.Total != 21 || p.Items[0].Name != "example.org" {
				t.Fatalf("zones: %v %v", p, err)
			}
		} else {
			p, err := c.DNSRecords(context.Background(), testZone, 2, "_acme-challenge")
			if err != nil || p.Info.Total != 21 || p.Items[0].Name != "example.org" {
				t.Fatalf("records: %v %v", p, err)
			}
		}
	}
}

func TestDNSWritesAndExport(t *testing.T) {
	var calls []string
	c := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/export") {
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "example.org. 300 IN TXT \"value\"\n")
			return
		}
		if r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"success":true,"result":{"id":"`+testRecord+`","name":"example.org","type":"TXT"}}`)
			return
		}
		if r.Method == "PATCH" || r.Method == "POST" {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
				return
			}
			if body["content"] != "test" || body["ttl"] != float64(300) {
				t.Error("missing value or TTL")
			}
			if r.Method == "PATCH" && len(body) != 2 {
				t.Error("patch would overwrite other record attributes")
			}
			if r.Method == "POST" && (body["type"] != "TXT" || body["name"] != "example.org") {
				t.Error("invalid create body")
			}
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"success":true,"result":{"id":"`+testRecord+`"}}`)
	})
	ctx := context.Background()
	id, err := c.CreateDNSRecord(ctx, testZone, RecordInput{Type: "TXT", Name: "example.org", Content: "test", TTL: 300})
	if err != nil || id != testRecord {
		t.Fatal(id, err)
	}
	if _, err = c.PatchDNSRecord(ctx, testZone, id, RecordPatch{Content: "test", TTL: 300}); err != nil {
		t.Fatal(err)
	}
	if _, err = c.DeleteDNSRecord(ctx, testZone, id); err != nil {
		t.Fatal(err)
	}
	text, err := c.ExportDNSZone(ctx, testZone)
	if err != nil || text != "example.org. 300 IN TXT \"value\"\n" {
		t.Fatal(text, err)
	}
	path := "/zones/" + testZone + "/dns_records"
	want := []string{"POST " + path, "GET " + path + "/" + id, "PATCH " + path + "/" + id, "GET " + path + "/" + id, "DELETE " + path + "/" + id, "GET " + path + "/export"}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected calls: %v", calls)
	}
}

func TestDNSFailureAndInvalidIDs(t *testing.T) {
	calls := 0
	c := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, "sensitive upstream diagnostic")
	})
	if _, err := c.DeleteDNSRecord(context.Background(), testZone, "../bad"); !errors.Is(err, ErrInvalidDNSRequest) {
		t.Fatal(err)
	}
	if _, err := c.DNSRecords(context.Background(), "../bad", 1, ""); !errors.Is(err, ErrInvalidDNSRequest) {
		t.Fatal(err)
	}
	if _, err := c.Zones(context.Background(), 0); !errors.Is(err, ErrInvalidDNSRequest) {
		t.Fatal(err)
	}
	_, err := c.DeleteDNSRecord(context.Background(), testZone, testRecord)
	if err == nil || strings.Contains(err.Error(), "sensitive") || !strings.Contains(err.Error(), "403") || calls != 1 {
		t.Fatal(err, calls)
	}
}

func TestGlobalCredentialsScopeAndZoneCreation(t *testing.T) {
	var secondCalls int
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { secondCalls++ }))
	defer second.Close()
	const account = "cccccccccccccccccccccccccccccccc"
	var creates int
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("X-Auth-Key") != "fixture-key" || r.Header.Get("X-Auth-Email") != "dns@example.test" || r.Header.Get("Authorization") != "" {
			t.Error("unexpected credential mode")
		}
		if r.URL.Path == "/accounts" {
			io.WriteString(w, `{"success":true,"result":[{"id":"`+account+`"}],"result_info":{"page":1,"total_count":1}}`)
			return
		}
		if r.Method == "POST" {
			var in struct {
				Name    string
				Account struct{ ID string }
			}
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Name != "example.test" || in.Account.ID != account {
				t.Error("incorrect zone create payload", err)
			}
			creates++
			io.WriteString(w, `{"success":true,"result":{"id":"`+testZone+`","name":"example.test","status":"pending"}}`)
			return
		}
		http.Redirect(w, r, second.URL, http.StatusTemporaryRedirect)
	}))
	defer local.Close()
	c, err := NewClient(WithGlobalAPIKey("dns@example.test", "fixture-key"))
	if err != nil {
		t.Fatal(err)
	}
	c.rc.SetBaseURL(local.URL)
	z, err := c.CreateZone(context.Background(), "EXAMPLE.test.")
	if err != nil || z.ID != testZone || creates != 1 {
		t.Fatal(z, err)
	}
	_, err = c.Zones(context.Background(), 1)
	if err == nil || secondCalls != 0 || strings.Contains(err.Error(), "fixture-key") {
		t.Fatal("credentials followed redirect", err)
	}
}

func TestStructuredDNSWrites(t *testing.T) {
	type fixture struct {
		kind, content string
		fields        map[string]any
	}
	examples := []fixture{
		{"CAA", `0 issue "example.test; parameter=A B"`, map[string]any{"flags": uint8(0), "tag": "issue", "value": "example.test; parameter=A B"}},
		{"SRV", "10 8 443 service.example.test.", map[string]any{"priority": uint16(10), "weight": uint16(8), "port": uint16(443), "target": "service.example.test."}},
		{"URI", `5 "https://example.test/path"`, map[string]any{"weight": uint16(5), "target": "https://example.test/path"}},
	}
	for _, ex := range examples {
		b, err := cloudflareContent(ex.kind, ex.content, nil)
		if err != nil {
			t.Fatal(ex.kind, err)
		}
		got, _ := json.Marshal(b["data"])
		want, _ := json.Marshal(ex.fields)
		if string(got) != string(want) {
			t.Fatal(ex.kind, string(got), string(want))
		}
	}
	if _, err := cloudflareContent("SRV", "10 443 missing", nil); err == nil {
		t.Fatal("incomplete SRV accepted")
	}
	for _, record := range []string{
		`{"id":"` + testRecord + `","name":"www.example.test","type":"A","meta":{"managed_by_apps":true}}`,
		`{"id":"` + testRecord + `","name":"www.example.test","type":"MX"}`,
		`{"id":"` + testRecord + `","name":"www.example.test"}`,
	} {
		c := localClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				t.Error("mutation after partial or managed record read")
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"success":true,"result":`+record+`}`)
		})
		if _, err := c.PatchDNSRecord(context.Background(), testZone, testRecord, RecordPatch{Content: "value", TTL: 300}); err == nil {
			t.Fatal("mutation succeeded")
		}
	}
}
