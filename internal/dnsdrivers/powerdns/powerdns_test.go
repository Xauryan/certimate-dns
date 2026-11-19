package powerdns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestRecordSetWritesAcrossResolvers(t *testing.T) {
	const zid = "example.test."
	const owner = "a.example.test."
	var mu sync.Mutex
	records := []record{{Content: "127.0.0.1", Disabled: true}}
	comments := []comment{{Content: "existing", Account: "user", ModifiedAt: 3}}
	writes := 0
	broken := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != zonesPath+"/"+zid || r.Header.Get("X-API-Key") != "synthetic-key" {
			t.Error("bad request")
			w.WriteHeader(400)
			return
		}
		if r.Method == "GET" {
			if broken {
				w.Write([]byte(`{"id":"example.test.","name":"example.test.","rrsets":[{"name":"a.example.test.","type":"A","ttl":60}]}`))
				return
			}
			json.NewEncoder(w).Encode(zone{ID: zid, Name: zid, RRSets: []rrset{{Name: owner, Type: "A", TTL: 60, Records: records, Comments: comments}}})
			return
		}
		if r.Method != "PATCH" {
			t.Error("unexpected method")
			w.WriteHeader(400)
			return
		}
		var body struct{ RRSets []rrset }
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.RRSets) != 1 {
			t.Error("bad payload")
			return
		}
		set := body.RRSets[0]
		if set.Type != "A" || set.Change != "REPLACE" || set.Name != owner || set.TTL != 60 || set.Comments != nil {
			t.Errorf("record set metadata changed: %+v", set)
			return
		}
		records = set.Records
		writes++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	a := &domain.Access{Config: map[string]any{"apiKey": "synthetic-key", "serverUrl": server.URL}}
	p, _ := New(a)
	other, _ := New(a)
	var wg sync.WaitGroup
	for i, provider := range []dns.Provider{p, other} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := provider.CreateDNSRecord(context.Background(), zid, dns.RecordInput{Name: owner, Type: "A", TTL: 60, Content: []string{"127.0.0.2", "127.0.0.3"}[i]})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if len(records) != 3 || !slices.Contains(records, record{Content: "127.0.0.1", Disabled: true}) {
		t.Fatal(records)
	}
	listed, err := p.DNSRecords(context.Background(), zid, 1, "a.example.test")
	if err != nil || len(listed.Items) != 3 || listed.Items[0].Description != "existing" {
		t.Fatalf("list %+v %v", listed, err)
	}
	id := listed.Items[0].ID
	if _, err = p.PatchDNSRecord(context.Background(), zid, id, dns.RecordPatch{Content: "127.0.0.6", TTL: 90}); err == nil {
		t.Fatal("changed sibling TTL")
	}
	replaced, err := p.PatchDNSRecord(context.Background(), zid, id, dns.RecordPatch{Content: "127.0.0.6", TTL: 60})
	if err != nil || replaced == id || len(records) != 3 || !records[0].Disabled {
		t.Fatalf("patch %v, %+v", err, records)
	}
	if _, err = p.DeleteDNSRecord(context.Background(), zid, replaced); err != nil || len(records) != 2 {
		t.Fatalf("delete %v, %+v", err, records)
	}
	if _, err = p.CreateDNSRecord(context.Background(), zid, dns.RecordInput{Name: "foreign.test", Type: "A", TTL: 60, Content: "127.0.0.1"}); err == nil {
		t.Fatal("foreign owner")
	}
	broken = true
	if _, err = p.CreateDNSRecord(context.Background(), zid, dns.RecordInput{Name: owner, Type: "A", TTL: 60, Content: "127.0.0.1"}); err == nil {
		t.Fatal("partial set accepted")
	}
	if writes != 4 {
		t.Fatalf("unexpected write count %d", writes)
	}
}
func TestTXTPresentationRoundTrip(t *testing.T) {
	value := strings.Repeat("ä", 166) + "\\\"\n\x00"
	if got := display("TXT", quoteTXT(value)); got != value {
		t.Errorf("TXT round trip %q", got)
	}
}
