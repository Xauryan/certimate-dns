package powerdns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	u "github.com/certimate-go/certimate/internal/dnsdrivers/selfhostutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestAtomicRecordMove(t *testing.T) {
	const zid = "example.test."
	notes := []comment{{Account: "operator", Content: "retain", ModifiedAt: 123}}
	src := rrset{Name: "mx.example.test.", Type: "MX", Records: []record{{Content: "10 old.example.test.", Disabled: true}, {Content: "20 backup.example.test."}}, TTL: 60, Comments: notes}
	dst := rrset{Name: "web.example.test.", Type: "A", Records: []record{{Content: "127.0.0.1"}}, TTL: 180, Comments: notes}
	writes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != zonesPath+"/"+zid {
			t.Error("incorrect zone")
			w.WriteHeader(400)
			return
		}
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(zone{ID: zid, Name: zid, RRSets: []rrset{src, dst}})
			return
		}
		if r.Method != "PATCH" {
			t.Error("unexpected write method")
			w.WriteHeader(400)
			return
		}
		writes++
		var sets struct{ RRSets []rrset }
		err := json.NewDecoder(r.Body).Decode(&sets)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if len(sets.RRSets) != 2 {
			t.Error("expected one atomic two-set patch")
			return
		}
		a, b := sets.RRSets[0], sets.RRSets[1]
		if a.Name != src.Name || a.TTL != 60 || b.Name != dst.Name || b.TTL != 180 || a.Change != "REPLACE" || b.Change != "REPLACE" ||
			a.Comments != nil || b.Comments != nil || !slices.Equal(a.Records, []record{{Content: "20 backup.example.test."}}) ||
			!slices.Equal(b.Records, []record{{Content: "127.0.0.1"}, {Content: "127.0.0.2", Disabled: true}}) {
			t.Errorf("unexpected updates %+v", sets.RRSets)
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	client, _ := u.NewClient(srv.URL)
	p := &provider{client: client}
	ctx := context.Background()
	prior := src.row(zid, src.Records[0])
	if prior.Content != "old.example.test" || prior.Priority == nil || *prior.Priority != 10 {
		t.Fatal("noncanonical MX", prior)
	}
	desired := dns.RecordInput{Name: "web.example.test", Type: "A", Content: "127.0.0.2", TTL: 180, Line: prior.Line, Description: prior.Description}
	id, err := p.ReplaceDNSRecord(ctx, zid, prior, desired)
	if err != nil || id == prior.ID || id != dst.row(zid, record{Content: desired.Content}).ID {
		t.Fatal(id, err)
	}
	desired.TTL = 300
	if _, err = p.ReplaceDNSRecord(ctx, zid, prior, desired); err == nil {
		t.Fatal("overwrote destination TTL")
	}
	desired.TTL = 180
	dst.Comments = nil
	if _, err = p.ReplaceDNSRecord(ctx, zid, prior, desired); err == nil {
		t.Fatal("overwrote comments")
	}
	if writes != 1 {
		t.Fatal(writes)
	}
}
