package tencenteo

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type mockTransport func(*http.Request) (*http.Response, error)

func (f mockTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type request struct {
	action   string
	want     string
	response string
}

func mock(t *testing.T, siteType string, steps ...request) *provider {
	t.Helper()
	p, err := New(&domain.Access{Config: map[string]any{"secretId": "synthetic-id", "secretKey": "synthetic-key", "siteType": siteType}})
	if err != nil {
		t.Fatal(err)
	}
	sdk := p.(*provider).sdk
	sdk.WithHttpTransport(mockTransport(func(r *http.Request) (*http.Response, error) {
		t.Helper()
		host := mainlandHost
		if siteType == "intl" {
			host = internationalHost
		}
		if r.URL.Host != host || r.URL.Scheme != "https" || r.Method != http.MethodPost || r.Header.Get("X-TC-Version") != "2022-09-01" || !strings.HasPrefix(r.Header.Get("Authorization"), "TC3-HMAC-SHA256 ") {
			t.Fatal("unexpected EdgeOne endpoint or missing signature")
		}
		if len(steps) == 0 {
			t.Fatal("unexpected provider request")
		}
		step := steps[0]
		steps = steps[1:]
		if action := r.Header.Get("X-TC-Action"); action != step.action {
			t.Fatalf("action %s, expected %s", action, step.action)
		}
		var got, want any
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(step.want), &want); err != nil {
			t.Fatal(err)
		}
		actual, _ := json.Marshal(got)
		expected, _ := json.Marshal(want)
		if string(actual) != string(expected) {
			t.Fatalf("%s body %s, expected %s", step.action, actual, expected)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(step.response)), Request: r}, nil
	}))
	t.Cleanup(func() {
		if len(steps) != 0 {
			t.Errorf("%d mock requests missing", len(steps))
		}
	})
	return p.(*provider)
}

const (
	zoneResponse   = `{"Response":{"TotalCount":1,"Zones":[{"ZoneId":"zone-demo","ZoneName":"example.test","Type":"full","Status":"active"}],"RequestId":"test"}}`
	zoneLookup     = `{"Offset":0,"Limit":20,"Filters":[{"Name":"zone-type","Values":["full"]},{"Name":"zone-id","Values":["zone-demo"]}]}`
	idLookup       = `{"ZoneId":"zone-demo","Offset":0,"Limit":20,"Filters":[{"Name":"id","Values":["record-demo"]}]}`
	recordResponse = `{"Response":{"TotalCount":1,"DnsRecords":[{"RecordId":"record-demo","ZoneId":"zone-demo","Name":"www.example.test","Type":"A","Location":"Default","Content":"127.0.0.2","TTL":120,"Status":"disable","Weight":0}],"RequestId":"test"}}`
	ack            = `{"Response":{"RequestId":"test"}}`
)

func TestZonesAndRecords(t *testing.T) {
	p := mock(t, "intl",
		request{"DescribeZones", `{"Offset":20,"Limit":20,"Filters":[{"Name":"zone-type","Values":["full"]}]}`, strings.Replace(zoneResponse, `"TotalCount":1`, `"TotalCount":21`, 1)},
		request{"DescribeZones", zoneLookup, zoneResponse},
		request{"DescribeDnsRecords", `{"ZoneId":"zone-demo","Offset":20,"Limit":20,"Filters":[{"Name":"name","Values":["www"],"Fuzzy":true}]}`, strings.Replace(recordResponse, `"TotalCount":1`, `"TotalCount":21`, 1)},
	)
	ctx := context.Background()
	z, err := p.Zones(ctx, 2)
	if err != nil || z.Info.Page != 2 || z.Info.Total != 21 || len(z.Items) != 1 || z.Items[0].Name != "example.test" {
		t.Fatalf("zones %#v, %v", z, err)
	}
	r, err := p.DNSRecords(ctx, "zone-demo", 2, "www")
	if err != nil || r.Info.Page != 2 || r.Info.Total != 21 || len(r.Items) != 1 || r.Items[0].Line != "Default" || r.Items[0].Status != "disable" {
		t.Fatalf("records %#v, %v", r, err)
	}
}

func TestWrites(t *testing.T) {
	p := mock(t, "cn",
		request{"DescribeZones", zoneLookup, zoneResponse},
		request{"CreateDnsRecord", `{"ZoneId":"zone-demo","Name":"www.example.test","Type":"A","Content":"127.0.0.1","TTL":300,"Location":"CN"}`, `{"Response":{"RecordId":"record-demo","RequestId":"test"}}`},
		request{"DescribeZones", zoneLookup, zoneResponse},
		request{"DescribeDnsRecords", idLookup, recordResponse},
		request{"ModifyDnsRecords", `{"ZoneId":"zone-demo","DnsRecords":[{"RecordId":"record-demo","Name":"www.example.test","Type":"A","Content":"127.0.0.1","TTL":300,"Location":"Default","Weight":0}]}`, ack},
		request{"DescribeZones", zoneLookup, zoneResponse},
		request{"DescribeDnsRecords", idLookup, recordResponse},
		request{"DeleteDnsRecords", `{"ZoneId":"zone-demo","RecordIds":["record-demo"]}`, ack},
	)
	ctx := context.Background()
	id, err := p.CreateDNSRecord(ctx, "zone-demo", dns.RecordInput{Name: "WWW.example.test.", Type: "A", Content: "127.0.0.1", TTL: 300, Line: "CN"})
	if err != nil || id != "record-demo" {
		t.Fatalf("create returned %q, %v", id, err)
	}
	if id, err := p.PatchDNSRecord(ctx, "zone-demo", id, dns.RecordPatch{Content: "127.0.0.1", TTL: 300}); err != nil || id != "record-demo" {
		t.Fatalf("patch returned %q, %v", id, err)
	}
	if id, err := p.DeleteDNSRecord(ctx, "zone-demo", id); err != nil || id != "record-demo" {
		t.Fatalf("delete returned %q, %v", id, err)
	}
}

func TestRejectMismatchedZoneAndRecords(t *testing.T) {
	ctx := context.Background()
	t.Run("CNAME site", func(t *testing.T) {
		p := mock(t, "", request{"DescribeZones", zoneLookup, strings.Replace(zoneResponse, `"full"`, `"partial"`, 1)})
		if _, err := p.DNSRecords(ctx, "zone-demo", 1, ""); err == nil {
			t.Fatal("accepted CNAME site")
		}
	})
	t.Run("record belongs to a different zone", func(t *testing.T) {
		p := mock(t, "", request{"DescribeZones", zoneLookup, zoneResponse}, request{"DescribeDnsRecords", idLookup, strings.Replace(recordResponse, "zone-demo", "zone-other", 1)})
		if _, err := p.DeleteDNSRecord(ctx, "zone-demo", "record-demo"); err == nil {
			t.Fatal("deleted foreign record")
		}
	})
	t.Run("record detail has different ID", func(t *testing.T) {
		p := mock(t, "", request{"DescribeZones", zoneLookup, zoneResponse}, request{"DescribeDnsRecords", idLookup, strings.Replace(recordResponse, "record-demo", "record-other", 1)})
		if _, err := p.PatchDNSRecord(ctx, "zone-demo", "record-demo", dns.RecordPatch{Content: "new", TTL: 300}); !errors.Is(err, domain.ErrRecordNotFound) {
			t.Fatal("accepted mismatched record ID")
		}
	})
	t.Run("record owner outside zone", func(t *testing.T) {
		p := mock(t, "", request{"DescribeZones", zoneLookup, zoneResponse})
		if _, err := p.CreateDNSRecord(ctx, "zone-demo", dns.RecordInput{Name: "www.badexample.test", Type: "TXT", Content: "new", TTL: 300}); !errors.Is(err, dns.ErrInvalidDNSRequest) {
			t.Fatal("accepted an out-of-zone name")
		}
	})
}

func TestCredentialAndEndpointValidation(t *testing.T) {
	for _, a := range []*domain.Access{nil, {}, {Config: map[string]any{"secretId": "synthetic"}}, {Config: map[string]any{"secretKey": "synthetic", "secretId": "synthetic", "siteType": "other.example"}}} {
		if _, err := New(a); !errors.Is(err, domain.ErrInvalidParams) {
			t.Fatal("accepted invalid account")
		}
	}
	for _, target := range []string{"http://" + mainlandHost + "/", "https://other.example/", "https://test@" + mainlandHost + "/"} {
		r, _ := http.NewRequest(http.MethodPost, target, nil)
		if _, err := dnsutil.SignedTransportFor(nil, mainlandHost).RoundTrip(r); err == nil {
			t.Fatal("accepted invalid destination")
		}
	}
	p := mock(t, "", request{"DescribeZones", zoneLookup, `{"Response":{"Error":{"Code":"TestFailure","Message":"sensitive provider diagnostic"},"RequestId":"test"}}`})
	if _, err := p.DNSRecords(context.Background(), "zone-demo", 1, ""); !errors.Is(err, errProvider) {
		t.Fatal("unexpected public error")
	}
}

func TestRecordMetadata(t *testing.T) {
	withDate := strings.Replace(recordResponse, `"Weight":0`, `"Weight":0,"ModifiedOn":"2026-01-02T03:04:05+08:00"`, 1)
	p := mock(t, "",
		request{"DescribeZones", zoneLookup, zoneResponse},
		request{"DescribeDnsRecords", `{"ZoneId":"zone-demo","Offset":0,"Limit":20}`, withDate},
		request{"DescribeZones", zoneLookup, zoneResponse},
		request{"DescribeDnsRecords", idLookup, recordResponse},
		request{"ModifyDnsRecordsStatus", `{"ZoneId":"zone-demo","RecordsToEnable":["record-demo"]}`, ack},
		request{"DescribeZones", zoneLookup, zoneResponse},
		request{"DescribeDnsRecords", idLookup, recordResponse},
		request{"ModifyDnsRecords", `{"ZoneId":"zone-demo","DnsRecords":[{"RecordId":"record-demo","Name":"www.example.test","Type":"A","Location":"Default","Content":"127.0.0.2","TTL":120,"Weight":17}]}`, ack},
		request{"DescribeZones", zoneLookup, zoneResponse},
		request{"DescribeDnsRecords", idLookup, recordResponse},
		request{"ModifyDnsRecords", `{"ZoneId":"zone-demo","DnsRecords":[{"RecordId":"record-demo","Name":"www.example.test","Type":"A","Location":"CN","Content":"127.0.0.2","TTL":120,"Weight":0}]}`, ack},
	)
	ctx := context.Background()
	rows, err := p.DNSRecords(ctx, "zone-demo", 1, "")
	if err != nil || rows.Items[0].Weight == nil || *rows.Items[0].Weight != 0 || rows.Items[0].UpdatedAt != "2026-01-01T19:04:05Z" {
		t.Fatal(rows, err)
	}
	for _, param := range [][2]string{{"status", "enabled"}, {"weight", "17"}, {"line", "CN"}} {
		if err := p.SetBatchAttribute(ctx, "zone-demo", "record-demo", param[0], param[1]); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMissingMXPriorityAndAmbiguousRecordStopsMutation(t *testing.T) {
	for _, body := range []string{strings.Replace(recordResponse, `"A"`, `"MX"`, 1), strings.Replace(recordResponse, `"TotalCount":1`, `"TotalCount":2`, 1)} {
		p := mock(t, "", request{"DescribeZones", zoneLookup, zoneResponse}, request{"DescribeDnsRecords", idLookup, body})
		if _, err := p.PatchDNSRecord(context.Background(), "zone-demo", "record-demo", dns.RecordPatch{Content: "test", TTL: 120}); err == nil {
			t.Fatal("accepted incomplete read")
		}
	}
}

func TestMXPriorityOnCreate(t *testing.T) {
	p := mock(t, "", request{"DescribeZones", zoneLookup, zoneResponse}, request{"CreateDnsRecord", `{"ZoneId":"zone-demo","Type":"MX","Name":"example.test","Content":"mail.example.test","TTL":300,"Priority":0}`, `{"Response":{"RecordId":"r1","RequestId":"test"}}`})
	priority := 0
	id, err := p.CreateDNSRecord(context.Background(), "zone-demo", dns.RecordInput{Name: "@", Type: "MX", Content: "0 mail.example.test", TTL: 300, Priority: &priority})
	if id != "r1" || err != nil {
		t.Fatal(id, err)
	}
}
