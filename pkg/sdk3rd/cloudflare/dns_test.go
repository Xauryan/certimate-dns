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
		if r.Method == "GET" {
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "example.org. 300 IN TXT \"value\"\n")
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
	want := []string{"POST " + path, "PATCH " + path + "/" + id, "DELETE " + path + "/" + id, "GET " + path + "/export"}
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
