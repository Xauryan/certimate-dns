package registrarutil_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsla"
	"github.com/certimate-go/certimate/internal/dnsdrivers/dynv6"
	"github.com/certimate-go/certimate/internal/dnsdrivers/namesilo"
	"github.com/certimate-go/certimate/internal/dnsdrivers/spaceship"
	"github.com/certimate-go/certimate/internal/dnsdrivers/west"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestRegistrarNativeEdits(t *testing.T) {
	const origin = "example.test"
	const oldMX = `{"id":7,"zoneID":42,"name":"mail","type":"MX","priority":3,"data":"mx.example.test."}`
	const nameSiloMX = "<resource_record><record_id>7</record_id><type>MX</type><host>mail.example.test</host><value>mx.example.test.</value><ttl>3600</ttl><distance>3</distance></resource_record>"
	account := map[string]any{"apiId": "sample", "apiSecret": "sample", "httpToken": "sample", "apiKey": "sample", "username": "sample", "apiPassword": "sample"}
	for _, c := range []struct {
		provider, zone string
		newProvider    func(*domain.Access) (dns.Provider, error)
		caps           dns.RecordEditCapabilities
	}{
		{"DNS.LA", "42", dnsla.New, dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true}},
		{"dynv6", origin, dynv6.New, dns.RecordEditCapabilities{Rename: true, Priority: true}},
		{"NameSilo", origin, namesilo.New, dns.RecordEditCapabilities{Rename: true, Priority: true}},
		{"West", origin, west.New, dns.RecordEditCapabilities{Retype: true, Priority: true}},
	} {
		t.Run(c.provider, func(t *testing.T) {
			writes := 0
			transport := &http.Transport{}
			transport.RegisterProtocol("https", roundTrip(func(r *http.Request) (*http.Response, error) {
				var payload string
				switch r.URL.Path {
				case "/api/domain":
					payload = `{"code":200,"data":{"id":"42","displayDomain":"example.test."}}`
				case "/api/recordList":
					payload = `{"code":200,"data":{"total":2,"results":[{"id":"7","domainId":"42","host":"mail","type":1,"data":"10.0.0.8","lineId":"telecom","weight":11,"ttl":300,"remark":"keep","disable":true},{"id":"8","domainId":"42","host":"mail","type":1,"data":"10.0.0.9","ttl":300}]}}`
				case "/api/record":
					var b map[string]any
					err := json.NewDecoder(r.Body).Decode(&b)
					if err != nil || r.Method != "PUT" || b["id"] != "7" || b["host"] != "changed" || b["type"] != float64(15) || b["data"] != "next.example.test." || b["preference"] != float64(11) || b["disable"] != true || b["weight"] != float64(11) || b["lineId"] != "telecom" || b["remark"] != "keep" {
						t.Error("DNS.LA rich edit lost metadata or targeted wrong record")
					}
					writes++
					payload = `{"code":200}`
				case "/api/v2/zones/by-name/example.test":
					payload = `{"id":42,"name":"example.test"}`
				case "/api/v2/zones/42/records":
					payload = "[" + oldMX + "]"
				case "/api/v2/zones/42/records/7":
					payload = oldMX
					if r.Method == "PATCH" {
						var b map[string]any
						err := json.NewDecoder(r.Body).Decode(&b)
						if err != nil || b["name"] != "changed" || b["type"] != nil || b["priority"] != float64(11) || b["data"] != "next.example.test." {
							t.Error("incorrect dynv6 rename/priority")
						}
						writes++
					}
				case "/api/dnsListRecords":
					payload = "<namesilo><reply><code>300</code>" + nameSiloMX + "</reply></namesilo>"
				case "/api/dnsUpdateRecord":
					q := r.URL.Query()
					if q.Get("domain") != origin || q.Get("rrid") != "7" || q.Get("rrhost") != "changed" || q.Get("rrvalue") != "next.example.test." || q.Get("rrdistance") != "11" || q.Has("rrtype") {
						t.Error("incorrect NameSilo rename/priority")
					}
					writes++
					payload = "<namesilo><reply><code>300</code><record_id>new-id</record_id></reply></namesilo>"
				case "/api/v2/domain/":
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					q := r.PostForm
					if q.Get("domain") != origin {
						t.Error("incorrect West.cn zone")
					}
					switch q.Get("act") {
					case "getdnsrecord":
						payload = `{"result":200,"data":{"total":"2","items":[{"id":"7","type":"A","item":"mail","value":"10.0.0.8","ttl":"300","line":"LTEL","pause":"1"},{"id":"8","type":"A","item":"mail","value":"10.0.0.9","ttl":"300","line":"LTEL","pause":"0"}]}}`
					case "moddnsrecord":
						if q.Get("id") != "7" || q.Get("type") != "MX" || q.Get("value") != "next.example.test." || q.Get("level") != "11" || q.Get("line") != "LTEL" || q.Has("host") {
							t.Error("incorrect West.cn retype/priority")
						}
						writes++
						payload = `{"result":200,"data":[]}`
					default:
						t.Errorf("unexpected West.cn action %q", q.Get("act"))
					}
				default:
					t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
				}
				return &http.Response{Request: r, StatusCode: 200, Body: io.NopCloser(strings.NewReader(payload)), Header: make(http.Header)}, nil
			}))
			p, err := c.newProvider(&domain.Access{Config: account, DNSManagementTransport: transport})
			if err != nil {
				t.Fatal(err)
			}
			e := p.(dns.RecordEditor)
			if e.RecordEditCapabilities() != c.caps {
				t.Fatal("incorrect native edit capabilities")
			}
			ctx := t.Context()
			rows, err := p.DNSRecords(ctx, c.zone, 1, "")
			if err != nil || len(rows.Items) < 1 {
				t.Fatalf("read prior: %v", err)
			}
			prior := rows.Items[0]
			pref := 11
			desired := dns.RecordInput{Name: prior.Name, Type: "MX", Content: "next.example.test.", TTL: prior.TTL, Priority: &pref, Weight: prior.Weight, Description: prior.Description, Line: prior.Line}
			if c.caps.Rename {
				desired.Name = "changed.example.test"
			}
			stale := prior
			stale.TTL++
			if _, err := e.ReplaceDNSRecord(ctx, c.zone, stale, desired); err == nil {
				t.Fatal("edited stale record")
			}
			drift := desired
			drift.Line = "different"
			if _, err := e.ReplaceDNSRecord(ctx, c.zone, prior, drift); err == nil {
				t.Fatal("accepted metadata change")
			}
			foreign := desired
			foreign.Name = "wrong.foreign.test"
			if _, err := e.ReplaceDNSRecord(ctx, c.zone, prior, foreign); err == nil {
				t.Fatal("edited outside zone")
			}
			if !c.caps.Retype {
				retype := desired
				retype.Type = "TXT"
				retype.Priority = nil
				if _, err := e.ReplaceDNSRecord(ctx, c.zone, prior, retype); err == nil {
					t.Fatal("accepted unsupported record type change")
				}
			}
			if !c.caps.Rename {
				rename := desired
				rename.Name = "changed.example.test"
				if _, err := e.ReplaceDNSRecord(ctx, c.zone, prior, rename); err == nil {
					t.Fatal("accepted unsupported owner change")
				}
			}
			if writes != 0 {
				t.Fatal("modified records while checking rejected edit")
			}
			id, err := e.ReplaceDNSRecord(ctx, c.zone, prior, desired)
			wantID := "7"
			if c.provider == "NameSilo" {
				wantID = "new-id"
			}
			if err != nil || id != wantID || writes != 1 {
				t.Fatalf("native edit %q, writes %d: %v", id, writes, err)
			}
		})
	}
	p, err := spaceship.New(&domain.Access{Config: account})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.(dns.RecordEditor); ok {
		t.Fatal("Spaceship cannot atomically change record identity")
	}
}
