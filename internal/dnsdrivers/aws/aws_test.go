package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

const testZone = "Z123"
const testSet = `<ResourceRecordSet><Name>www.example.test.</Name><Type>TXT</Type><SetIdentifier>east</SetIdentifier><Weight>7</Weight><TTL>60</TTL><ResourceRecords><ResourceRecord><Value>"old"</Value></ResourceRecord><ResourceRecord><Value>"sibling"</Value></ResourceRecord></ResourceRecords><HealthCheckId>check</HealthCheckId></ResourceRecordSet>`

func TestRoute53ValueScopedTransaction(t *testing.T) {
	ctx := t.Context()
	writes := 0
	sets := testSet
	var want []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Error("unsigned request")
		}
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/rrset"):
			fmt.Fprintf(w, `<ListResourceRecordSetsResponse><ResourceRecordSets>%s</ResourceRecordSets><IsTruncated>false</IsTruncated></ListResourceRecordSetsResponse>`, sets)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/rrset"):
			writes++
			var req struct {
				Changes []struct {
					Action string
					Set    struct {
						Policy        string `xml:"SetIdentifier"`
						Weight        int
						HealthCheckId string
						Values        []string `xml:"ResourceRecords>ResourceRecord>Value"`
					} `xml:"ResourceRecordSet"`
				} `xml:"ChangeBatch>Changes>Change"`
			}
			if err := xml.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			if len(req.Changes) != 2 {
				t.Errorf("change count %d", len(req.Changes))
				return
			}
			for _, c := range req.Changes {
				if c.Set.Policy != "east" || c.Set.Weight != 7 || c.Set.HealthCheckId != "check" {
					t.Error("routing policy lost")
				}
			}
			if req.Changes[0].Action != "DELETE" || !reflect.DeepEqual(req.Changes[0].Set.Values, []string{`"old"`, `"sibling"`}) {
				t.Error("missing exact-match old RRset")
			}
			if req.Changes[1].Action != "CREATE" || !reflect.DeepEqual(req.Changes[1].Set.Values, want) {
				t.Errorf("replacement values %v", req.Changes[1].Set.Values)
			}
			fmt.Fprint(w, `<ChangeResourceRecordSetsResponse><ChangeInfo><Id>change</Id><Status>PENDING</Status><SubmittedAt>2025-01-01T00:00:00Z</SubmittedAt></ChangeInfo></ChangeResourceRecordSetsResponse>`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	raw, err := New(&domain.Access{Config: map[string]any{"accessKeyId": "test-id", "secretAccessKey": "synthetic-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*provider)
	opts := p.client.Options()
	opts.BaseEndpoint = sdk.String(server.URL)
	p.client = route53.New(opts)
	rows, err := p.DNSRecords(ctx, testZone, 1, "www")
	if err != nil || len(rows.Items) != 2 {
		t.Fatal(rows, err)
	}
	id := rows.Items[0].ID
	if _, err = p.DeleteDNSRecord(ctx, "ZOTHER", id); err == nil {
		t.Fatal("cross-zone edit allowed")
	}
	if _, err = p.PatchDNSRecord(ctx, testZone, id, dns.RecordPatch{Content: "new", TTL: 61}); err == nil {
		t.Fatal("per-value patch altered sibling TTL")
	}
	want = []string{`"new"`, `"sibling"`}
	next, err := p.PatchDNSRecord(ctx, testZone, id, dns.RecordPatch{Content: "new", TTL: 60})
	if err != nil || next == id {
		t.Fatal(next, err)
	}
	want = []string{`"sibling"`}
	if _, err = p.DeleteDNSRecord(ctx, testZone, id); err != nil {
		t.Fatal(err)
	}
	sets = strings.ReplaceAll(testSet, `<Value>"sibling"</Value>`, "")
	if _, err = p.DeleteDNSRecord(ctx, testZone, id); err == nil {
		t.Fatal("partial response caused a write")
	}
	if writes != 2 {
		t.Fatalf("writes %d", writes)
	}
}

func TestZoneDetailsCreateAndPagination(t *testing.T) {
	index := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST":
			var v struct{ Name, CallerReference string }
			if e := xml.NewDecoder(r.Body).Decode(&v); e != nil || v.Name != "new.test" || v.CallerReference == "" {
				t.Error("bad create request")
			}
			fmt.Fprint(w, `<CreateHostedZoneResponse><HostedZone><Name>new.test.</Name><Id>/hostedzone/ZNEW</Id></HostedZone></CreateHostedZoneResponse>`)
		case strings.HasSuffix(r.URL.Path, "/Z123"):
			fmt.Fprint(w, `<GetHostedZoneResponse><HostedZone><Id>/hostedzone/Z123</Id><Name>example.test.</Name></HostedZone><DelegationSet><NameServers><NameServer>ns.test</NameServer></NameServers></DelegationSet></GetHostedZoneResponse>`)
		default:
			index++
			if index == 1 {
				fmt.Fprint(w, `<ListHostedZonesResponse><HostedZones><HostedZone><Id>/hostedzone/Z123</Id><Name>example.test.</Name></HostedZone></HostedZones><IsTruncated>true</IsTruncated><NextMarker>more</NextMarker></ListHostedZonesResponse>`)
				return
			}
			if r.URL.Query().Get("marker") != "more" {
				t.Error("missing marker")
			}
			fmt.Fprint(w, `<ListHostedZonesResponse><HostedZones><HostedZone><Id>/hostedzone/Z456</Id><Name>other.test.</Name></HostedZone></HostedZones><IsTruncated>false</IsTruncated></ListHostedZonesResponse>`)
		}
	}))
	defer srv.Close()
	raw, _ := New(&domain.Access{Config: map[string]any{"accessKeyId": "test-id", "secretAccessKey": "test-key"}})
	p := raw.(*provider)
	opts := p.client.Options()
	opts.BaseEndpoint = sdk.String(srv.URL)
	p.client = route53.New(opts)
	zones, err := p.Zones(t.Context(), 1)
	if err != nil || zones.Info.Total != 2 {
		t.Fatal(zones, err)
	}
	detail, err := p.ZoneDetails(t.Context(), testZone)
	if err != nil || len(detail.Nameservers) != 1 {
		t.Fatal(detail, err)
	}
	z, err := p.CreateZone(t.Context(), "New.Test.")
	if err != nil || z.ID != "ZNEW" {
		t.Fatal(z, err)
	}
}
