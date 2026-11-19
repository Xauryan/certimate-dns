package dnsmanagement

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestAliReplacePreservesRecordAndNativeLine(t *testing.T) {
	writes := 0
	p := testAli(t, func(r *http.Request) (*http.Response, error) {
		switch aliAction(r) {
		case "DescribeDomainInfo":
			return jsonRPC(`{"DomainName":"example.test","ResourceGroupId":"fixture-group"}`), nil
		case "DescribeDomainRecordInfo":
			return jsonRPC(`{"RecordId":"234","DomainName":"example.test","Type":"A","RR":"old","Value":"127.0.0.1","TTL":600,"Line":"telecom","Locked":false,"Status":"DISABLE","GroupId":"17","Remark":"keep"}`), nil
		case "UpdateDomainRecord":
			q := r.URL.Query()
			if q.Get("RR") != "new" || q.Get("Type") != "MX" || q.Get("Priority") != "12" || q.Get("Value") != "mx.example.test" || q.Get("Line") != "telecom" || q.Get("RecordId") != "234" || q.Has("GroupId") || q.Has("Status") || q.Has("Remark") {
				t.Error("unexpected native edit fields")
			}
			writes++
			return jsonRPC(`{"RecordId":"234"}`), nil
		default:
			t.Fatal("unexpected provider operation")
			return nil, nil
		}
	})
	prior := dns.DNSRecord{ID: "234", Type: "A", Name: "old.example.test", Content: "127.0.0.1", TTL: 600, Line: "telecom", Status: "DISABLE", Description: "keep"}
	desired := dns.RecordInput{Name: "new.example.test", Type: "MX", Content: "mx.example.test", TTL: 600, Priority: ptr(12), Line: prior.Line, Description: prior.Description}
	ctx := context.Background()
	if id, err := p.ReplaceDNSRecord(ctx, "example.test", prior, desired); err != nil || id != prior.ID {
		t.Fatal(id, err)
	}
	desired.Name = "outside.example.org"
	if _, err := p.ReplaceDNSRecord(ctx, "example.test", prior, desired); err == nil {
		t.Fatal("out-of-zone rename accepted")
	}
	desired.Name = "new.example.test"
	prior.Content = "127.0.0.2"
	if _, err := p.ReplaceDNSRecord(ctx, "example.test", prior, desired); err == nil || writes != 1 {
		t.Fatal("stale record changed")
	}
}

func TestDNSPodReplaceKeepsStatusRemarkAndWeight(t *testing.T) {
	writes := 0
	p := testTencent(t, func(r *http.Request) (*http.Response, error) {
		switch r.Header.Get("X-TC-Action") {
		case "DescribeRecord":
			return jsonRPC(`{"Response":{"RecordInfo":{"Id":234,"SubDomain":"old","RecordType":"MX","RecordLine":"联通","RecordLineId":"10=1","Value":"mx.example.test","MX":7,"TTL":300,"Enabled":0,"Weight":11,"Remark":"keep"},"RequestId":"fixture"}}`), nil
		case "ModifyRecord":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			for k, v := range map[string]any{"Domain": "example.test", "RecordId": float64(234), "SubDomain": "new", "RecordType": "MX", "MX": float64(2), "RecordLine": "联通", "RecordLineId": "10=1", "Weight": float64(11), "Remark": "keep", "Status": "DISABLE", "Value": "mx2.example.test", "TTL": float64(600)} {
				if body[k] != v {
					t.Errorf("missing native edit field %s", k)
				}
			}
			if _, ok := body["GroupId"]; ok {
				t.Error("overwriting group")
			}
			writes++
			return jsonRPC(`{"Response":{"RecordId":234,"RequestId":"fixture"}}`), nil
		default:
			t.Fatal("unexpected provider operation")
			return nil, nil
		}
	})
	prior := dns.DNSRecord{ID: "234", Type: "MX", Name: "old.example.test", Content: "mx.example.test", TTL: 300, Status: "DISABLE", Line: "10=1", Priority: ptr(7), Weight: ptr(11), Description: "keep"}
	desired := dns.RecordInput{Name: "new.example.test", Type: "MX", Content: "mx2.example.test", TTL: 600, Priority: ptr(2), Line: prior.Line, Weight: prior.Weight, Description: prior.Description}
	ctx := context.Background()
	if _, err := p.ReplaceDNSRecord(ctx, "example.test", prior, desired); err != nil {
		t.Fatal(err)
	}
	desired.Type = "TXT"
	desired.Priority = nil
	if _, err := p.ReplaceDNSRecord(ctx, "example.test", prior, desired); err == nil || writes != 1 {
		t.Fatal("changed weighted record type")
	}
}
