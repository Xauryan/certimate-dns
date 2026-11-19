package baidu

import (
	"context"
	"testing"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestReplaceRecordPreservesLineStatusAndRemark(t *testing.T) {
	p := fixture(t,
		exchange{"GET", recordPath, "id=r1&maxKeys=1000", "", inventory},
		exchange{"PUT", recordPath + "/r1", "", `{"rr":"mail","type":"TXT","value":"new","ttl":600,"description":"previous note"}`, ""},
		exchange{"GET", recordPath, "id=r1&maxKeys=1000", "", inventory},
		exchange{"GET", recordPath, "id=r1&maxKeys=1000", "", inventory},
	)
	preference := 3
	prior := dns.DNSRecord{ID: "r1", Name: "example.test", Type: "MX", Content: "mx.example.test", TTL: 300, Line: "ct", Status: "running", Description: "previous note", Priority: &preference}
	desired := dns.RecordInput{Name: "mail.example.test", Type: "TXT", Content: "new", TTL: 600, Line: "ct", Description: "previous note"}
	ctx := context.Background()
	id, err := p.ReplaceDNSRecord(ctx, "example.test", prior, desired)
	if err != nil || id != "r1" {
		t.Fatal(id, err)
	}
	desired.Name = "elsewhere.test"
	if _, err = p.ReplaceDNSRecord(ctx, "example.test", prior, desired); err == nil {
		t.Fatal("accepted foreign owner")
	}
	desired.Name = "mail.example.test"
	prior.Description = "changed"
	if _, err = p.ReplaceDNSRecord(ctx, "example.test", prior, desired); err == nil {
		t.Fatal("accepted stale record")
	}
}
