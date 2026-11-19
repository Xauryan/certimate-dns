package qingcloud

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestRichEditUsesNativeIDAndVerifiesReassignedValue(t *testing.T) {
	const initial = `{"domain_record_id":91,"zone_name":"example.test.","domain_name":"mx.example.test.","rd_type":"MX","mode":1,"view_id":2,"ttl":600,"record":[{"weight":0,"group_status":1,"data":[{"record_value_id":6,"status":1,"value":"10 old."}]}]}`
	updated := false
	calls := 0
	p := fixture(t, func(r *http.Request) string {
		switch r.URL.Path {
		case "/v1/dns/host/":
			if r.URL.Query().Get("domain_name") != "new.example.test" {
				t.Fatal("wrong destination check")
			}
			return `{"total_count":0,"domains":[]}`
		case "/v1/dr_id/91":
			if r.Method == "POST" {
				calls++
				var b map[string]any
				if json.NewDecoder(r.Body).Decode(&b) != nil || b["domain_name"] != "new" || b["ttl"] != float64(300) || b["type"] != "TXT" || b["view_id"] != float64(2) || b["mode"] != float64(1) {
					t.Fatal("invalid native update")
				}
				var groups []writeGroup
				if json.Unmarshal([]byte(b["record"].(string)), &groups) != nil || groups[0].Values[0].Value != strconv.Quote("hello") {
					t.Fatal("wrong TXT format")
				}
				updated = true
				return `{"code":0}`
			}
			state := initial
			if updated {
				state = strings.NewReplacer("mx.example.test.", "new.example.test.", `"MX"`, `"TXT"`, `"10 old."`, `"\"hello\""`, `"ttl":600`, `"ttl":300`, `"record_value_id":6`, `"record_value_id":7`).Replace(state)
			}
			return `{"code":0,"data":` + state + `}`
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
			return ""
		}
	})
	pref := 10
	prior := dns.DNSRecord{ID: "91_6", Type: "MX", Name: "mx.example.test", TTL: 600, Content: "old.", Priority: &pref, Line: "2", Status: "enabled"}
	desired := dns.RecordInput{Type: "TXT", Name: "new.example.test", TTL: 300, Content: "hello", Line: "2"}
	id, err := p.ReplaceDNSRecord(context.Background(), "example.test", prior, desired)
	if err != nil || id != "91_7" || calls != 1 {
		t.Fatalf("id=%q writes=%d err=%v", id, calls, err)
	}
}

func TestRichEditRejectsSharedIdentityAndStaleValue(t *testing.T) {
	p := fixture(t, func(r *http.Request) string {
		if r.Method != "GET" || r.URL.Path != "/v1/dr_id/91" {
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
		return `{"code":0,"data":` + twoValues + `}`
	})
	pref := 10
	prior := dns.DNSRecord{ID: "91_6", Type: "MX", Name: "mx.example.test", TTL: 600, Content: "old.", Priority: &pref, Line: "2", Status: "enabled"}
	desired := dns.RecordInput{Type: "MX", Name: "new.example.test", TTL: 600, Content: "next.", Line: "2", Priority: &pref}
	if _, err := p.ReplaceDNSRecord(context.Background(), "example.test", prior, desired); err == nil {
		t.Fatal("renamed siblings")
	}
	prior.Content = "stale."
	desired.Name = "mx.example.test"
	if _, err := p.ReplaceDNSRecord(context.Background(), "example.test", prior, desired); err == nil {
		t.Fatal("overwrote changed value")
	}
}

func TestRichPriorityChangePreservesSecondMXValue(t *testing.T) {
	updated := false
	p := fixture(t, func(r *http.Request) string {
		if r.URL.Path != "/v1/dr_id/91" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Method == "POST" {
			var b map[string]any
			if json.NewDecoder(r.Body).Decode(&b) != nil || b["record"] != `[{"weight":5,"values":[{"value":"32 old.","status":1},{"value":"20 sibling.","status":2}]}]` {
				t.Fatal("MX sibling or status changed")
			}
			updated = true
			return `{"code":0}`
		}
		s := twoValues
		if updated {
			s = strings.Replace(s, "10 old.", "32 old.", 1)
		}
		return `{"code":0,"data":` + s + `}`
	})
	old, newPriority := 10, 32
	prior := dns.DNSRecord{ID: "91_6", Type: "MX", Name: "mx.example.test", TTL: 600, Content: "old.", Priority: &old, Line: "2", Status: "enabled"}
	desired := dns.RecordInput{Type: "MX", Name: "mx.example.test", TTL: 600, Content: "old.", Line: "2", Priority: &newPriority}
	id, err := p.ReplaceDNSRecord(context.Background(), "example.test", prior, desired)
	if err != nil || id != "91_6" || !updated {
		t.Fatalf("unexpected ID %s error %v", id, err)
	}
}
