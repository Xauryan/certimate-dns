package dnsdrivers_test

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/dnsdrivers/aws"
	"github.com/certimate-go/certimate/internal/dnsdrivers/huawei"
	"github.com/certimate-go/certimate/internal/dnsdrivers/huoshan"
	"github.com/certimate-go/certimate/internal/dnsdrivers/jdcloud"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type richWire func(*http.Request) string

func (w richWire) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(w(r)))}, nil
}

func richProvider(t *testing.T, newProvider func(*domain.Access) (dns.Provider, error), f richWire) dns.Provider {
	t.Helper()
	transport := &http.Transport{}
	transport.RegisterProtocol("https", f)
	p, err := newProvider(&domain.Access{Config: map[string]any{"accessKeyId": "id", "secretAccessKey": "key", "accessKeySecret": "key"}, DNSManagementTransport: transport})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func exerciseEdit(t *testing.T, p dns.Provider, zone, typ, content string, priority *int) (dns.DNSRecord, string) {
	t.Helper()
	ctx := t.Context()
	rows, err := p.DNSRecords(ctx, zone, 1, "")
	if err != nil || len(rows.Items) == 0 {
		t.Fatal(rows, err)
	}
	prior := rows.Items[0]
	editor := p.(dns.RecordEditor)
	if flags := editor.RecordEditCapabilities(); !flags.Rename || !flags.Retype || !flags.Priority {
		t.Fatal(flags)
	}
	desired := dns.RecordInput{Name: "new.example.test", Type: typ, Content: content, Priority: priority, TTL: prior.TTL, Line: prior.Line, Weight: prior.Weight, Description: prior.Description}
	stale := prior
	stale.TTL++
	if _, err := editor.ReplaceDNSRecord(ctx, zone, stale, desired); err == nil {
		t.Fatal("stale snapshot edited")
	}
	changingLine := desired
	changingLine.Line += "other"
	if _, err := editor.ReplaceDNSRecord(ctx, zone, prior, changingLine); err == nil {
		t.Fatal("routing change accepted")
	}
	escaped := desired
	escaped.Name = "other.test"
	if _, err := editor.ReplaceDNSRecord(ctx, zone, prior, escaped); err == nil {
		t.Fatal("cross-zone move accepted")
	}
	id, err := editor.ReplaceDNSRecord(ctx, zone, prior, desired)
	if err != nil || id == "" {
		t.Fatal(id, err)
	}
	return prior, id
}

func TestRoute53RichEditMovesValueInSingleTransaction(t *testing.T) {
	makeSet := func(name, typ string, values ...string) string {
		var records string
		for _, v := range values {
			records += "<ResourceRecord><Value>" + v + "</Value></ResourceRecord>"
		}
		return fmt.Sprintf("<ResourceRecordSet><Name>%s.</Name><Type>%s</Type><SetIdentifier>east</SetIdentifier><Weight>7</Weight><TTL>600</TTL><HealthCheckId>check</HealthCheckId><ResourceRecords>%s</ResourceRecords></ResourceRecordSet>", name, typ, records)
	}
	old := makeSet("www.example.test", "A", "10.0.0.1", "10.0.0.2")
	dest := makeSet("new.example.test", "MX", "3 old.test.")
	writes := 0
	p := richProvider(t, aws.New, func(r *http.Request) string {
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/rrset") {
			set := old
			if strings.HasPrefix(r.URL.Query().Get("name"), "new.") {
				set = dest
			}
			return "<ListResourceRecordSetsResponse><ResourceRecordSets>" + set + "</ResourceRecordSets><IsTruncated>false</IsTruncated></ListResourceRecordSetsResponse>"
		}
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/Z1") {
			return "<GetHostedZoneResponse><HostedZone><Name>example.test.</Name><Id>/hostedzone/Z1</Id></HostedZone></GetHostedZoneResponse>"
		}
		if r.Method != "POST" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		writes++
		var req struct {
			Changes []struct {
				Action string
				Set    struct {
					Name, Type, SetIdentifier, HealthCheckId string
					Weight, TTL                              int
					Values                                   []string `xml:"ResourceRecords>ResourceRecord>Value"`
				} `xml:"ResourceRecordSet"`
			} `xml:"ChangeBatch>Changes>Change"`
		}
		if e := xml.NewDecoder(r.Body).Decode(&req); e != nil || len(req.Changes) != 4 {
			t.Fatalf("invalid transaction %+v %v", req, e)
		}
		for i, c := range req.Changes {
			if c.Set.HealthCheckId != "check" || c.Set.Weight != 7 || c.Set.SetIdentifier != "east" || c.Set.TTL != 600 {
				t.Error("lost routing configuration")
			}
			expected := []struct {
				action, owner, typ string
				values             []string
			}{
				{"DELETE", "www.example.test.", "A", []string{"10.0.0.1", "10.0.0.2"}},
				{"CREATE", "www.example.test.", "A", []string{"10.0.0.2"}},
				{"DELETE", "new.example.test.", "MX", []string{"3 old.test."}},
				{"CREATE", "new.example.test.", "MX", []string{"3 old.test.", "21 mx.test."}},
			}[i]
			if c.Action != expected.action || c.Set.Name != expected.owner || c.Set.Type != expected.typ || !reflect.DeepEqual(c.Set.Values, expected.values) {
				t.Errorf("change %d %+v", i, c)
			}
		}
		return "<ChangeResourceRecordSetsResponse><ChangeInfo><Id>change</Id><Status>PENDING</Status><SubmittedAt>2025-01-01T00:00:00Z</SubmittedAt></ChangeInfo></ChangeResourceRecordSetsResponse>"
	})
	n := 21
	prior, id := exerciseEdit(t, p, "Z1", "MX", "mx.test.", &n)
	if prior.ID == id || writes != 1 {
		t.Fatal("replacement ID or write count incorrect")
	}
	dest = strings.ReplaceAll(dest, "<Weight>7", "<Weight>8")
	editor := p.(dns.RecordEditor)
	if _, err := editor.ReplaceDNSRecord(t.Context(), "Z1", prior, dns.RecordInput{Name: "new.example.test", Type: "MX", Content: "21 mx.test.", TTL: 600, Weight: prior.Weight, Line: "east"}); err == nil || writes != 1 {
		t.Fatal("incompatible destination policy")
	}
}

func TestHuaweiRichEditRejectsMultiAnswerIdentityChange(t *testing.T) {
	const zone = `{"id":"z","name":"example.test.","zone_type":"public"}`
	row := `{"id":"r","zone_id":"z","zone_name":"example.test.","name":"www.example.test.","type":"A","records":["10.0.0.1"],"ttl":600,"default":false,"weight":3,"line":"Dianxin","description":"retain","status":"DISABLE"}`
	writes := 0
	p := richProvider(t, huawei.New, func(r *http.Request) string {
		switch r.Method + " " + r.URL.Path {
		case "GET /v2/zones/z":
			return zone
		case "GET /v2.1/zones/z/recordsets":
			return `{"recordsets":[` + row + `],"metadata":{"total_count":1}}`
		case "GET /v2.1/zones/z/recordsets/r":
			return row
		case "PUT /v2.1/zones/z/recordsets/r":
			writes++
			var b map[string]any
			if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
				t.Fatal(err)
			}
			want := map[string]any{"name": "new.example.test.", "type": "MX", "ttl": float64(600), "records": []any{"21 mx.test."}}
			if !reflect.DeepEqual(b, want) {
				t.Errorf("unexpected payload %v", b)
			}
			return row
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			return "{}"
		}
	})
	n := 21
	prior, id := exerciseEdit(t, p, "z", "MX", "mx.test.", &n)
	if id != prior.ID || writes != 1 {
		t.Fatal("unexpected ID/writes")
	}
	row = strings.Replace(row, `"10.0.0.1"]`, `"10.0.0.1","10.0.0.2"]`, 1)
	rows, err := p.DNSRecords(t.Context(), "z", 1, "")
	if err != nil {
		t.Fatal(err)
	}
	prior = rows.Items[0]
	if _, err = p.(dns.RecordEditor).ReplaceDNSRecord(t.Context(), "z", prior, dns.RecordInput{Name: "new.example.test", Type: "MX", Content: "21 mx.test", TTL: 600, Line: prior.Line, Weight: prior.Weight, Description: prior.Description}); err == nil || writes != 1 {
		t.Fatal("multi-answer move accepted")
	}
}

func TestVolcengineRichEditPreservesStatusAndRemarks(t *testing.T) {
	const row = `{"RecordID":"1","Host":"www","Type":"A","Value":"10.0.0.1","TTL":600,"Enable":false,"Line":"default","Remark":"retain","Weight":7}`
	writes := 0
	p := richProvider(t, huoshan.New, func(r *http.Request) string {
		var result string
		switch r.URL.Query().Get("Action") {
		case "ListZones":
			result = `{"Total":1,"Zones":[{"ZID":1,"ZoneName":"example.test"}]}`
		case "ListRecords":
			result = `{"TotalCount":1,"Records":[` + row + `]}`
		case "UpdateRecord":
			writes++
			var b map[string]any
			if e := json.NewDecoder(r.Body).Decode(&b); e != nil {
				t.Fatal(e)
			}
			want := map[string]any{"RecordID": "1", "Host": "new", "Type": "AAAA", "Value": "::1", "TTL": float64(600), "Line": "default", "Remark": "retain", "Weight": float64(7)}
			if !reflect.DeepEqual(b, want) {
				t.Errorf("unexpected payload %v", b)
			}
			result = row
		default:
			t.Error("unexpected action")
			result = "{}"
		}
		return `{"ResponseMetadata":{"RequestID":"test"},"Result":` + result + "}"
	})
	prior, id := exerciseEdit(t, p, "example.test", "AAAA", "::1", nil)
	if prior.ID != id || writes != 1 {
		t.Fatal("unexpected ID/write count")
	}
}

func TestJDCloudRichEditPreservesNativeAttributes(t *testing.T) {
	const row = `{"id":1,"hostRecord":"www","type":"SRV","hostValue":"target.test.","mxPriority":12,"port":80,"weight":3,"jcloudRes":false,"ttl":600,"viewValue":[0,-1],"resolvingStatus":4}`
	writes := 0
	p := richProvider(t, jdcloud.New, func(r *http.Request) string {
		var result string
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/domain"):
			result = `{"totalCount":1,"dataList":[{"id":7,"domainName":"example.test"}]}`
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/ResourceRecord"):
			result = `{"totalCount":1,"dataList":[` + row + `]}`
		case r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/ResourceRecord/1"):
			writes++
			var b struct{ Req map[string]any }
			if e := json.NewDecoder(r.Body).Decode(&b); e != nil {
				t.Fatal(e)
			}
			want := map[string]any{"domainName": "example.test", "hostRecord": "new", "type": "MX", "hostValue": "mx.test.", "mxPriority": float64(21), "ttl": float64(600), "viewValue": float64(-1), "jcloudRes": false}
			if !reflect.DeepEqual(b.Req, want) {
				t.Errorf("unexpected payload %v", b.Req)
			}
			result = "{}"
		default:
			t.Error("unexpected JDCloud request")
			result = "{}"
		}
		return `{"requestId":"request","result":` + result + "}"
	})
	n := 21
	prior, id := exerciseEdit(t, p, "7", "MX", "mx.test.", &n)
	if prior.Weight != nil || prior.Content != "12 3 80 target.test." {
		t.Fatal("SRV's RDATA weight leaked into routing metadata", prior)
	}
	if prior.ID != id || writes != 1 {
		t.Fatal("unexpected ID/write count")
	}
}
