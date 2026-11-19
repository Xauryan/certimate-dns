package dnsmanagement

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type mockRPC func(*http.Request) (*http.Response, error)

func (m mockRPC) RoundTrip(req *http.Request) (*http.Response, error)               { return m(req) }
func (m mockRPC) Call(req *http.Request, _ *http.Transport) (*http.Response, error) { return m(req) }

func jsonRPC(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func aliAction(r *http.Request) string {
	// The Alibaba SDK populates lowercase header map keys before RoundTrip.
	for k, v := range r.Header {
		if strings.EqualFold(k, "x-acs-action") && len(v) > 0 {
			return v[0]
		}
	}
	return r.URL.Query().Get("Action")
}
func testAli(t *testing.T, transport mockRPC) *Aliyun {
	t.Helper()
	p, err := NewAliyun(&domain.Access{Config: map[string]any{"accessKeyId": "fixture-id", "accessKeySecret": "fixture-secret", "resourceGroupId": "fixture-group"}})
	if err != nil {
		t.Fatal(err)
	}
	p.sdk.HttpClient = transport
	return p
}

func TestAliDNSZoneAndRecordScope(t *testing.T) {
	const zone = "example.test"
	for _, data := range []string{
		`{"RecordId":"234","DomainName":"other.test","RR":"www","Type":"TXT","Line":"default","Locked":false}`,
		`{"RecordId":"234","DomainName":"example.test","RR":"www","Line":"default","Locked":false}`,
		`{"RecordId":"234","DomainName":"example.test","RR":"www","Type":"TXT","Line":"default","Locked":true}`,
	} {
		gets := 0
		p := testAli(t, func(r *http.Request) (*http.Response, error) {
			action := aliAction(r)
			switch action {
			case "DescribeDomainInfo":
				return jsonRPC(`{"DomainName":"example.test","ResourceGroupId":"fixture-group"}`), nil
			case "DescribeDomainRecordInfo":
				gets++
				return jsonRPC(data), nil
			default:
				t.Fatal("unexpected write", action)
				return nil, nil
			}
		})
		if _, err := p.DeleteDNSRecord(context.Background(), zone, "234"); err == nil || gets != 1 {
			t.Fatalf("failed scope check, reads=%d err=%v", gets, err)
		}
	}
	p := testAli(t, func(r *http.Request) (*http.Response, error) {
		if aliAction(r) != "AddDomain" || r.URL.Query().Get("DomainName") != zone || r.URL.Query().Get("ResourceGroupId") != "fixture-group" {
			t.Error("missing explicit group on zone creation")
		}
		return jsonRPC(`{"DomainId":"42","DomainName":"example.test"}`), nil
	})
	got, err := p.CreateZone(context.Background(), "EXAMPLE.test.")
	if err != nil || got.ID != zone {
		t.Fatal(got, err)
	}
}

func TestAliDNSMXPreserved(t *testing.T) {
	p := testAli(t, func(r *http.Request) (*http.Response, error) {
		switch aliAction(r) {
		case "DescribeDomainInfo":
			return jsonRPC(`{"DomainName":"example.test","ResourceGroupId":"fixture-group"}`), nil
		case "DescribeDomainRecordInfo":
			return jsonRPC(`{"RecordId":"234","DomainName":"example.test","Type":"MX","RR":"mail","Priority":12,"Line":"telecom","Locked":false}`), nil
		case "UpdateDomainRecord":
			q := r.URL.Query()
			if q.Get("RR") != "mail" || q.Get("Line") != "telecom" || q.Get("Priority") != "12" || q.Get("RecordId") != "234" || q.Get("Value") != "mx2.example.test" {
				t.Error("lost record metadata on update")
			}
			return jsonRPC(`{"RecordId":"234"}`), nil
		default:
			t.Fatal("unexpected action")
			return nil, nil
		}
	})
	_, err := p.PatchDNSRecord(context.Background(), "example.test", "234", dns.RecordPatch{Content: "mx2.example.test", TTL: 300})
	if err != nil {
		t.Fatal(err)
	}
}

func testTencent(t *testing.T, transport mockRPC) *Tencent {
	t.Helper()
	p, err := NewTencent(&domain.Access{Config: map[string]any{"secretId": "fixture-id", "secretKey": "fixture-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	p.sdk.WithHttpTransport(transport)
	return p
}

func TestDNSPodLineWeightAndIncompleteDetail(t *testing.T) {
	writes := 0
	p := testTencent(t, func(r *http.Request) (*http.Response, error) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["Domain"] != "example.test" {
			t.Error("incorrect zone")
		}
		switch r.Header.Get("X-TC-Action") {
		case "CreateRecord":
			if body["SubDomain"] != "www" || body["RecordType"] != "显性URL" || body["RecordLineId"] != "10=1" || body["Weight"] != float64(7) || body["Remark"] != "fixture" {
				t.Error("lost input attributes")
			}
			writes++
			return jsonRPC(`{"Response":{"RecordId":234,"RequestId":"fixture"}}`), nil
		case "DescribeRecord":
			return jsonRPC(`{"Response":{"RecordInfo":{"Id":234,"RecordType":"MX","RecordLine":"默认","SubDomain":"mail","Enabled":1},"RequestId":"fixture"}}`), nil
		default:
			t.Fatal("unexpected mutation after partial read")
			return nil, nil
		}
	})
	ctx := context.Background()
	id, err := p.CreateDNSRecord(ctx, "example.test", dns.RecordInput{Name: "www.example.test", Type: "REDIRECT_URL", Content: "https://example.test", TTL: 600, Weight: ptr(7), Description: "fixture", Line: "10=1"})
	if err != nil || id != "234" {
		t.Fatal(id, err)
	}
	if _, err = p.PatchDNSRecord(ctx, "example.test", id, dns.RecordPatch{Content: "mail.example.test", TTL: 300}); err == nil || writes != 1 {
		t.Fatal("unexpected partial read result", err)
	}
}

func TestProviderTransportErrorsStayRedacted(t *testing.T) {
	transport := func(*http.Request) (*http.Response, error) { return nil, errors.New("fixture-secret upstream detail") }
	a := testAli(t, transport)
	b := testTencent(t, transport)
	for _, p := range []dns.Provider{a, b} {
		_, err := p.Zones(context.Background(), 1)
		if err == nil || strings.Contains(err.Error(), "fixture-secret") {
			t.Fatal("upstream error exposed")
		}
	}
}
