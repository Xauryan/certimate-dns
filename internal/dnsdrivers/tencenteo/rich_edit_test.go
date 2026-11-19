package tencenteo

import (
	"context"
	"testing"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestRichEditRetainsRoutingAndRejectsLossyRetype(t *testing.T) {
	p := mock(t, "", request{"DescribeZones", zoneLookup, zoneResponse}, request{"DescribeDnsRecords", idLookup, recordResponse},
		request{"ModifyDnsRecords", `{"ZoneId":"zone-demo","DnsRecords":[{"RecordId":"record-demo","Name":"mail.example.test","Type":"CNAME","Location":"Default","Weight":0,"TTL":600,"Content":"target.example.test"}]}`, ack},
		request{"DescribeZones", zoneLookup, zoneResponse}, request{"DescribeDnsRecords", idLookup, recordResponse},
		request{"DescribeZones", zoneLookup, zoneResponse}, request{"DescribeDnsRecords", idLookup, recordResponse},
	)
	ctx := context.Background()
	w := 0
	prior := dns.DNSRecord{ID: "record-demo", Name: "www.example.test", Type: "A", Content: "127.0.0.2", TTL: 120, Line: "Default", Status: "disable", Weight: &w}
	desired := dns.RecordInput{Name: "mail.example.test", Type: "CNAME", Content: "target.example.test", TTL: 600, Line: "Default", Weight: &w}
	id, err := p.ReplaceDNSRecord(ctx, "zone-demo", prior, desired)
	if err != nil || id != "record-demo" {
		t.Fatal(id, err)
	}
	desired.Type = "TXT"
	if _, err = p.ReplaceDNSRecord(ctx, "zone-demo", prior, desired); err == nil {
		t.Fatal("new type would discard traffic weight")
	}
	desired.Type = "CNAME"
	prior.Status = "enable"
	if _, err = p.ReplaceDNSRecord(ctx, "zone-demo", prior, desired); err == nil {
		t.Fatal("accepted stale record status")
	}
}
