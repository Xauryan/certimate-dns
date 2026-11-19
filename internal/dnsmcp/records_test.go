package dnsmcp

import (
	"context"
	"testing"

	"github.com/certimate-go/certimate/internal/dnsauth"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestRecordLegacyShapeAndBoundary(t *testing.T) {
	z := dnsauth.Zone{Name: "example.test", Provider: "cloudflare"}
	r := dns.DNSRecord{ID: "r1", Name: "www_pause.example.test.", Type: "CNAME", Proxied: true, Description: "service", UpdatedAt: "time"}
	row := recordRow(r, z)
	if row["Domain"] != "example.test" || row["Name"] != "www" || row["Status"] != "0" || row["Line"] != "1" || row["Remark"] != "service" || row["UpdateTime"] != "time" {
		t.Fatalf("legacy row %#v", row)
	}
	input := object{"record": "www good.example.test\nforeign.test. good.example.test", "type": "CNAME"}
	if _, problem := createWrites(z, input, true); problem != invalid {
		t.Fatal("unexpected batch accepted")
	}
	input = object{"name": "@", "type": "MX", "value": "smtp.example.test.", "mx": "20", "remark": "mail"}
	ch, problem := createWrites(z, input, false)
	if problem != nil || len(ch) != 1 || ch[0].input.Priority == nil || *ch[0].input.Priority != 20 || ch[0].input.Description != "mail" {
		t.Fatalf("legacy MX %#v, %v", ch, problem)
	}
}

type recordStub struct {
	dns.Provider
	records []dns.DNSRecord
}

func (s recordStub) DNSRecords(_ context.Context, _ string, n int, _ string) (*dns.DNSPage[dns.DNSRecord], error) {
	return &dns.DNSPage[dns.DNSRecord]{Info: dns.PageInfo{Page: n, Total: len(s.records)}, Items: s.records}, nil
}

func TestRecordInventoryFailsClosed(t *testing.T) {
	z := dnsauth.Zone{Name: "example.test", ZoneID: "z", Provider: "aliyun"}
	r := dns.DNSRecord{Name: "other.test", ID: "r1", Type: "A"}
	p := recordStub{records: []dns.DNSRecord{r}}
	if _, err := authorizedRecords(context.Background(), p, z); err != upstream {
		t.Fatal("returned record outside authorized zone")
	}
	if _, err := recordTargets(object{"records": []object{{"RecordId": "r1"}, {"RecordId": "r1"}}}, map[string]dns.DNSRecord{"r1": r}); err != invalid {
		t.Fatal("duplicate target accepted")
	}
	if _, err := recordTargets(object{"records": []object{{"RecordId": "unknown"}}}, map[string]dns.DNSRecord{"r1": r}); err != missing {
		t.Fatal("unknown record accepted")
	}
	r.Name = z.Name
	r.TTL = 600
	_, err := editWrites(t.Context(), p, z, scope{}, object{"name": "x", "value": "127.0.0.1"}, []dns.DNSRecord{r})
	if err != unsupported {
		t.Fatal("unsupported rename accepted")
	}
}

func TestRecordProviderPageSizes(t *testing.T) {
	pages := 0
	out, err := providerPage(18, 3, func(page int) (*dns.DNSPage[int], error) {
		pages++
		start := (page - 1) * dns.DNSPageSize
		data := make([]int, min(dns.DNSPageSize, 25-start))
		for i := range data {
			data[i] = start + i
		}
		return &dns.DNSPage[int]{Info: dns.PageInfo{Page: page, Total: 25}, Items: data}, nil
	}, func(n int) object { return object{"n": n} })
	if err != nil || pages != 2 || out["total"] != 25 {
		t.Fatalf("page %#v %v", out, err)
	}
	rows := out["rows"].([]object)
	if len(rows) != 3 || rows[0]["n"] != 18 || rows[2]["n"] != 20 {
		t.Fatal(rows)
	}
}

type planEditor struct {
	recordStub
	limits dns.RecordEditCapabilities
}

func (m planEditor) RecordEditCapabilities() dns.RecordEditCapabilities { return m.limits }
func (m planEditor) ReplaceDNSRecord(context.Context, string, dns.DNSRecord, dns.RecordInput) (string, error) {
	panic("planning must not mutate the provider")
}

func TestRecordRichEditPlan(t *testing.T) {
	z := dnsauth.Zone{Name: "example.test", Provider: "cloudflare"}
	x := 20
	p := planEditor{limits: dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true}}
	prior := dns.DNSRecord{ID: "one", Name: "old.example.test", Type: "MX", TTL: 300, Priority: &x, Content: "20 old-mx.example.test.", Description: "mail", Line: "0"}
	args := object{"name": "new", "type": "MX", "value": "new-mx.example.test.", "mx": "40"}
	w, problem := editWrites(t.Context(), p, z, scope{}, args, []dns.DNSRecord{prior})
	if problem != nil || len(w) != 1 || w[0].action != "replace" {
		t.Fatalf("plan: %+v %v", w, problem)
	}
	in := w[0].input
	if in.Content != "new-mx.example.test." || in.Name != "new.example.test" || in.TTL != 300 || in.Priority == nil || *in.Priority != 40 || in.Description != "mail" || in.Line != "0" {
		t.Fatalf("planned data %+v", in)
	}
	args["value"] = "42 new-mx.example.test."
	if _, err := editWrites(t.Context(), p, z, scope{}, args, []dns.DNSRecord{prior}); err != invalid {
		t.Fatal("conflicting embedded and explicit priority accepted")
	}
	p.limits.Priority = false
	args["value"] = "new-mx.example.test."
	if _, err := editWrites(t.Context(), p, z, scope{}, args, []dns.DNSRecord{prior}); err != unsupported {
		t.Fatal("unsupported priority change accepted")
	}
	p.limits.Priority = true
	args["name"] = "other.test."
	if _, err := editWrites(t.Context(), p, z, scope{}, args, []dns.DNSRecord{prior}); err != invalid {
		t.Fatal("out-of-zone rename accepted")
	}
	prior.Name = "old_pause.example.test"
	prior.Type = "CNAME"
	prior.Priority = nil
	args = object{"name": "new", "type": "A", "value": "127.0.0.1"}
	w, problem = editWrites(t.Context(), p, z, scope{}, args, []dns.DNSRecord{prior})
	if problem != nil || len(w) != 1 || w[0].input.Name != "new_pause.example.test" {
		t.Fatalf("pause preservation %+v %v", w, problem)
	}
}

func TestRecordEditByNameFallback(t *testing.T) {
	z := dnsauth.Zone{Provider: "cloudflare", Name: "example.test"}
	rows := []dns.DNSRecord{
		{ID: "a", Name: "www.example.test", Type: "A", Proxied: true},
		{ID: "aaaa", Name: "www.example.test", Type: "AAAA", Line: "0"},
		{ID: "mx", Name: "www.example.test", Type: "MX", Line: "0"},
		{ID: "other", Name: "other.example.test", Type: "CNAME", Line: "0"},
	}
	for typ, want := range map[string]string{"A": "a", "CNAME": "aaaa", "MX": "mx"} {
		got := recordsByName(z, rows, "www.example.test", typ)
		if len(got) != 1 || got[0].ID != want {
			t.Fatalf("%s targets %+v", typ, got)
		}
	}
}
