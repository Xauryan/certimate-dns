package namesilo

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestRecordLifecycle(t *testing.T) {
	const zone = "example.test"
	const key = "synthetic-test-key"
	host := zone
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("key") != key || q.Get("version") != "1" || q.Get("type") != "xml" || r.Method != "GET" {
			t.Error("incorrect request")
		}
		reply := func(body string) { fmt.Fprintf(w, "<namesilo><reply><code>300</code>%s</reply></namesilo>", body) }
		switch r.URL.Path {
		case "/listDomains":
			reply("<domains><domain created='2001-01-01'>example.test</domain></domains><pager><total>1</total></pager>")
		case "/dnsListRecords":
			if q.Get("domain") != zone {
				t.Error("wrong zone")
			}
			reply("<resource_record><record_id>existing</record_id><type>MX</type><host>" + host + "</host><value>mx.example.test.</value><ttl>3600</ttl><distance>5</distance></resource_record>")
		case "/dnsUpdateRecord", "/dnsAddRecord":
			if q.Get("rrhost") != "" || q.Get("rrttl") != "7200" || q.Get("rrvalue") != "mail.example.test." || q.Get("rrdistance") != "20" || q.Get("domain") != zone {
				t.Error("wrong record write")
			}
			writes++
			reply("<record_id>new-id</record_id>")
		case "/dnsDeleteRecord":
			if q.Get("rrid") != "existing" || q.Get("domain") != zone {
				t.Error("incorrect delete")
			}
			writes++
			reply("")
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	raw, err := New(&domain.Access{Config: map[string]any{"apiKey": key}})
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*provider)
	p.api.Base = server.URL + "/"
	ctx := t.Context()
	zones, err := p.Zones(ctx, 1)
	if err != nil || len(zones.Items) != 1 || zones.Items[0].Name != zone {
		t.Fatalf("zones: %v", err)
	}
	rows, err := p.DNSRecords(ctx, zone, 1, "")
	if err != nil || rows.Items[0].Content != "5 mx.example.test." {
		t.Fatalf("list: %v", err)
	}
	priority := 20
	id, err := p.CreateDNSRecord(ctx, zone, dns.RecordInput{Name: zone, Type: "MX", Content: "mail.example.test.", Priority: &priority, TTL: 7200})
	if err != nil || id != "new-id" {
		t.Fatalf("create: %v", err)
	}
	id, err = p.PatchDNSRecord(ctx, zone, "existing", dns.RecordPatch{Content: "20 mail.example.test.", TTL: 7200})
	if err != nil || id != "new-id" {
		t.Fatalf("patch replaced ID: %v", err)
	}
	host = "foreign.test"
	if _, err := p.DeleteDNSRecord(ctx, zone, "existing"); err == nil || writes != 2 {
		t.Fatal("removed cross-zone record")
	}
	host = zone
	if _, err := p.DeleteDNSRecord(ctx, zone, "existing"); err != nil || writes != 3 {
		t.Fatalf("delete: %v", err)
	}
	server.Close()
	if _, err := p.Zones(ctx, 1); err == nil || strings.Contains(err.Error(), key) {
		t.Fatal("transport error includes credential")
	}
}
