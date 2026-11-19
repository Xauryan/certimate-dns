package qingcloud

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func fixture(t *testing.T, fn func(*http.Request) string) *provider {
	t.Helper()
	p, err := New(&domain.Access{Config: map[string]any{"accessKeyId": "test-key", "secretAccessKey": "synthetic-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	client := p.(*provider)
	client.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.URL.Host != "api.routewize.com" {
			t.Fatalf("unexpected endpoint %s", r.URL.Host)
		}
		mac := hmac.New(sha256.New, []byte("synthetic-secret"))
		io.WriteString(mac, r.Method+"\n"+r.Header.Get("Date")+"\n"+r.URL.RequestURI())
		if r.Header.Get("Authorization") != "QC-HMAC-SHA256 test-key:"+base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
			t.Fatal("wrong signature")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(fn(r))), Header: make(http.Header)}, nil
	})
	return client
}

const twoValues = `{"domain_record_id":91,"zone_name":"example.test.","domain_name":"mx.example.test.","rd_type":"MX","mode":1,"view_id":2,"ttl":600,"record":[{"weight":5,"group_status":1,"data":[{"record_value_id":6,"status":1,"value":"10 old."},{"record_value_id":7,"status":2,"value":"20 sibling."}]}]}`

func TestPatchPreservesSiblingsAndReturnsReplacementID(t *testing.T) {
	writes := 0
	p := fixture(t, func(r *http.Request) string {
		if r.URL.Path != "/v1/dr_id/91" {
			t.Fatalf("path %q", r.URL.Path)
		}
		if r.Method == "GET" {
			d := twoValues
			if writes > 0 {
				d = strings.ReplaceAll(strings.ReplaceAll(d, "10 old.", "10 new."), `"record_value_id":6`, `"record_value_id":8`)
			}
			return `{"code":0,"data":` + d + `}`
		}
		var data struct {
			Record, DomainName, ZoneName string
			Line                         int
		}
		var body map[string]json.RawMessage
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Fatal("invalid body")
		}
		for k, out := range map[string]any{"record": &data.Record, "domain_name": &data.DomainName, "zone_name": &data.ZoneName, "view_id": &data.Line} {
			if json.Unmarshal(body[k], out) != nil {
				t.Fatalf("bad %s", k)
			}
		}
		if data.DomainName != "mx" || data.ZoneName != "example.test." || data.Line != 2 || data.Record != `[{"weight":5,"values":[{"value":"10 new.","status":1},{"value":"20 sibling.","status":2}]}]` {
			t.Fatalf("invalid replacement %v", data)
		}
		writes++
		return `{"code":0}`
	})
	id, err := p.PatchDNSRecord(context.Background(), "example.test", "91_6", dns.RecordPatch{TTL: 600, Content: "new."})
	if err != nil || id != "91_8" || writes != 1 {
		t.Fatalf("got %s, %v, writes %d", id, err, writes)
	}
}

func TestMutationRequiresCompleteScopedSnapshot(t *testing.T) {
	tests := map[string]string{
		"foreign zone":         strings.ReplaceAll(twoValues, "example.test.", "other.test."),
		"foreign host":         strings.Replace(twoValues, "mx.example.test.", "other.test.", 1),
		"wrong record":         strings.Replace(twoValues, `"domain_record_id":91`, `"domain_record_id":7`, 1),
		"missing sibling data": strings.Replace(twoValues, `"value":"20 sibling."`, `"missing":null`, 1),
		"ambiguous value id":   strings.Replace(twoValues, `"record_value_id":7`, `"record_value_id":6`, 1),
		"missing group":        strings.Replace(twoValues, `"record":`, `"partial":`, 1),
		"paused group":         strings.Replace(twoValues, `"group_status":1`, `"group_status":2`, 1),
	}
	for name, snapshot := range tests {
		t.Run(name, func(t *testing.T) {
			p := fixture(t, func(r *http.Request) string {
				if r.Method != "GET" {
					t.Fatal("unexpected write")
				}
				return `{"code":0,"data":` + snapshot + `}`
			})
			_, err := p.DeleteDNSRecord(context.Background(), "example.test", "91_6")
			if err == nil {
				t.Fatal("unsafe snapshot allowed")
			}
		})
	}
}

func TestReadInventoryRequiresCompleteHostPages(t *testing.T) {
	p := fixture(t, func(r *http.Request) string {
		switch r.URL.Path {
		case "/v1/dns/host/":
			return `{"domains":[{"domain_name":"mx.example.test.","zone_name":"example.test."}],"total_count":1}`
		case "/v1/dns/host_info/":
			return `{"code":0,"records":[` + twoValues + `],"total_count":1}`
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
			return ""
		}
	})
	data, err := p.DNSRecords(context.Background(), "example.test", 1, "")
	if err != nil || data.Info.Total != 2 || data.Items[1].Status != "disabled" || *data.Items[1].Priority != 20 {
		t.Fatalf("data %v err %v", data, err)
	}
	p = fixture(t, func(r *http.Request) string { return `{"domains":[],"total_count":2}` })
	if _, err = p.DNSRecords(context.Background(), "example.test", 1, ""); err == nil {
		t.Fatal("accepted truncated inventory")
	}
}

func TestCreateSelectsValueAndStatusTargetsOnlyThatValue(t *testing.T) {
	p := fixture(t, func(r *http.Request) string {
		switch r.URL.Path {
		case "/v1/record/":
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["record"] != `[{"weight":2,"values":[{"value":"10.0.0.1","status":1}]}]` || body["mode"] != float64(3) {
				t.Fatalf("invalid create body %v", body)
			}
			return `{"code":0,"domain_record_id":91,"records":[{"value":[{"id":6,"value":"10.0.0.1"}]}]}`
		case "/v1/dr_id/91":
			return `{"code":0,"data":` + twoValues + `}`
		case "/v1/change_record_status/":
			var body struct {
				Target, Action string
				IDs            []int
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Target != "value" || body.Action != "stop" || len(body.IDs) != 1 || body.IDs[0] != 6 {
				t.Fatalf("bad status update %v", body)
			}
			return `{"code":0}`
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
			return ""
		}
	})
	n := 2
	id, err := p.CreateDNSRecord(context.Background(), "example.test", dns.RecordInput{Type: "A", Name: "www.example.test", Content: "10.0.0.1", TTL: 600, Weight: &n})
	if id != "91_6" || err != nil {
		t.Fatalf("unexpected create %s %v", id, err)
	}
	if _, err = p.SetDNSRecordStatus(context.Background(), "example.test", id, false); err != nil {
		t.Fatal(err)
	}
}

func TestNoDisclosureFromUpstreamErrors(t *testing.T) {
	p := fixture(t, func(*http.Request) string { return `{"code":29,"msg":"synthetic-secret"}` })
	if _, err := p.Zones(context.Background(), 1); !errors.Is(err, errResponse) || strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatal("provider error escaped")
	}
	if _, err := New(nil); !errors.Is(err, domain.ErrInvalidParams) {
		t.Fatal("missing credentials accepted")
	}
}

func TestZoneDiscoveryAndEmptyCreateAcknowledgement(t *testing.T) {
	for _, test := range []struct {
		suffix string
		valid  bool
	}{{"example.test.", true}, {"other-example.test.", false}} {
		p := fixture(t, func(r *http.Request) string {
			switch r.URL.Path {
			case "/v1/zone/":
				return ""
			case "/v1/user/zones":
				if r.URL.Query().Get("zone_name") != "example.test" {
					t.Fatal("unscoped create readback")
				}
				return `{"code":0,"zones":[{"zone_name":"` + test.suffix + `","service_status":"enabled"}],"total_count":1}`
			case "/v1/zone/view/":
				if r.URL.Query().Get("zone_name") != "example.test." {
					t.Fatal("wrong zone")
				}
				return `{"code":0,"zone_name":"example.test.","zone_views":[{"id":0,"name":"*"},{"id":2,"name":"Telecom"}]}`
			default:
				t.Fatalf("unexpected path %s", r.URL.Path)
				return ""
			}
		})
		z, err := p.CreateZone(context.Background(), "example.test")
		if test.valid {
			if err != nil || z == nil || z.Name != "example.test" || z.Status != "enabled" {
				t.Fatalf("bad zone %v %v", z, err)
			}
			d, err := p.ZoneDetails(context.Background(), z.ID)
			if err != nil || len(d.Lines) != 2 || d.Lines[1].ID != "2" || d.MinTTL != 60 {
				t.Fatalf("bad zone details %v %v", d, err)
			}
		} else if err == nil {
			t.Fatal("accepted fuzzy match as created zone")
		}
	}
}
