package aliyunesa

import (
	"context"
	"net/url"
	"strings"
	"testing"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestRichEditMXPriority(t *testing.T) {
	p, w := fixture(t)
	w.record = `{"SiteId":81,"RecordId":45,"RecordName":"www.example.test","RecordType":"MX","Comment":"note","Data":{"Value":"mx.example.test","Priority":4},"Ttl":300}`
	oldPriority, newPriority := 4, 12
	prior := dns.DNSRecord{ID: "45", Name: "www.example.test", Type: "MX", Content: "4 mx.example.test", Priority: &oldPriority, TTL: 300, Line: "0", Status: "active", Description: "note"}
	desired := dns.RecordInput{Name: prior.Name, Type: "MX", Content: "mx2.example.test", Priority: &newPriority, TTL: 600, Line: "0", Description: "note"}
	w.check = func(action string, q url.Values) {
		if action == "UpdateRecord" && (q.Get("Data") != `{"Priority":12,"Value":"mx2.example.test"}` || q.Has("Comment") || q.Has("Proxied") || q.Has("AuthConf") || q.Has("Type")) {
			t.Fatal("unintended metadata or record data change")
		}
	}
	ctx := context.Background()
	id, err := p.ReplaceDNSRecord(ctx, "81", prior, desired)
	if err != nil || id != "45" || w.writes != 1 {
		t.Fatal(id, err)
	}
	desired.Name = "other.example.test"
	if _, err = p.ReplaceDNSRecord(ctx, "81", prior, desired); err == nil {
		t.Fatal("accepted rename")
	}
	desired.Name, desired.Type = prior.Name, "TXT"
	if _, err = p.ReplaceDNSRecord(ctx, "81", prior, desired); err == nil {
		t.Fatal("accepted retype")
	}
	desired.Type = "MX"
	w.record = strings.Replace(w.record, `"note"`, `"changed"`, 1)
	if _, err = p.ReplaceDNSRecord(ctx, "81", prior, desired); err == nil || w.writes != 1 {
		t.Fatal("accepted stale record")
	}
}
