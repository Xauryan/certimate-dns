package aliyunesa

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

// wireAPI receives the request after the official SDK has serialized and signed it.
type wireAPI struct {
	t      *testing.T
	site   string
	record string
	check  func(action string, q url.Values)
	writes int
}

const fixtureSite = `{"SiteId":81,"SiteName":"example.test","AccessType":"NS","ResourceGroupId":"group-a","Status":"online","PlanName":"test-plan"}`
const fixtureRecord = `{"RecordId":45,"SiteId":81,"SiteName":"example.test","RecordName":"www.example.test","RecordType":"A/AAAA","Proxied":true,"BizName":"api","Comment":"sample note","Ttl":300,"Data":{"Value":"2001:db8:1::a"}}`

func (w *wireAPI) Call(r *http.Request, _ *http.Transport) (*http.Response, error) {
	w.t.Helper()
	// Tea preserves the SDK header key casing until the HTTP wire.
	headers := make(http.Header)
	for name, values := range r.Header {
		for _, value := range values {
			headers.Add(name, value)
		}
	}
	action := headers.Get("x-acs-action")
	if r.URL.Host != "esa.cn-hangzhou.aliyuncs.com" || r.URL.Scheme != "https" || headers.Get("Authorization") == "" || headers.Get("x-acs-version") != "2024-09-10" {
		w.t.Fatalf("unexpected endpoint or unsigned request for %s", action)
	}
	if w.check != nil {
		w.check(action, r.URL.Query())
	}
	var body string
	switch action {
	case "ListSites":
		body = `{"Sites":[` + w.site + `],"TotalCount":21}`
	case "GetSite":
		body = `{"SiteModel":` + w.site + `}`
	case "ListRecords":
		body = `{"Records":[` + w.record + `],"TotalCount":21}`
	case "GetRecord":
		body = `{"RecordModel":` + w.record + `}`
	case "CreateRecord":
		w.writes++
		body = `{"RecordId":65,"RequestId":"sample"}`
	case "UpdateRecord", "DeleteRecord":
		w.writes++
		body = `{"RequestId":"sample"}`
	default:
		w.t.Fatalf("unexpected action %s", action)
	}
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

func fixture(t *testing.T) (*provider, *wireAPI) {
	t.Helper()
	v, err := New(&domain.Access{Config: map[string]any{"accessKeyId": "sample-id", "accessKeySecret": "sample-key", "resourceGroupId": "group-a"}})
	if err != nil {
		t.Fatal(err)
	}
	p := v.(*provider)
	w := &wireAPI{t: t, site: fixtureSite, record: fixtureRecord}
	p.sdk.HttpClient = w
	return p, w
}

func TestScopedInventoryAndWrites(t *testing.T) {
	p, w := fixture(t)
	ctx := context.Background()
	w.check = func(action string, q url.Values) {
		switch action {
		case "ListSites":
			if q.Get("PageNumber") != "2" || q.Get("PageSize") != "20" || q.Get("AccessType") != "NS" || q.Get("ResourceGroupId") != "group-a" {
				t.Error("site listing lost its page or authorization scope")
			}
		case "GetSite", "ListRecords", "CreateRecord":
			if q.Get("SiteId") != "81" {
				t.Error("site-scoped action omitted the site")
			}
		case "GetRecord", "UpdateRecord", "DeleteRecord":
			if q.Get("RecordId") != "45" {
				t.Error("action targeted the wrong record")
			}
		}
		switch action {
		case "ListRecords":
			if q.Get("PageNumber") != "2" || q.Get("RecordName") != "www.example.test" {
				t.Error("record list filter or page omitted")
			}
		case "CreateRecord":
			if q.Get("Type") != "A/AAAA" || q.Get("RecordName") != "www.example.test" || q.Get("BizName") != "web" || q.Get("Proxied") != "true" || q.Get("Data") != `{"Value":"2001:db8:1::b"}` {
				t.Error("wrong create payload")
			}
		case "UpdateRecord":
			if q.Get("Data") != `{"Value":"2001:db8:1::c"}` || q.Get("Ttl") != "600" || q.Has("BizName") || q.Has("Proxied") || q.Has("Comment") || q.Has("AuthConf") {
				t.Error("patch changed metadata or dropped the value/TTL")
			}
		}
	}
	zs, err := p.Zones(ctx, 2)
	if err != nil || zs.Info.Total != 21 || len(zs.Items) != 1 || zs.Items[0].ID != "81" {
		t.Fatalf("zone list: %+v %v", zs, err)
	}
	s, err := p.ZoneDetails(ctx, "81")
	if err != nil || s.Name != "example.test" || s.Status != "online" || s.Plan != "test-plan" || len(s.Lines) != 2 || s.MinTTL != 1 {
		t.Fatalf("zone detail: %+v %v", s, err)
	}
	rs, err := p.DNSRecords(ctx, "81", 2, "www")
	if err != nil || len(rs.Items) != 1 {
		t.Fatalf("record list: %v", err)
	}
	r := rs.Items[0]
	if r.ID != "45" || r.Type != "AAAA" || r.Content != "2001:db8:1::a" || !r.Proxied || r.Line != "1" || r.TTL != 300 || r.Description != "sample note" || rs.Info.Total != 21 {
		t.Fatalf("record projection: %+v", r)
	}
	id, err := p.CreateDNSRecord(ctx, "81", dns.RecordInput{Name: "www.example.test.", Type: "AAAA", Content: "2001:db8:1::b", TTL: 300, Line: "1"})
	if err != nil || id != "65" {
		t.Fatalf("create: %q %v", id, err)
	}
	id, err = p.PatchDNSRecord(ctx, "81", "45", dns.RecordPatch{Content: "2001:db8:1::c", TTL: 600})
	if err != nil || id != "45" {
		t.Fatalf("patch: %q %v", id, err)
	}
	id, err = p.DeleteDNSRecord(ctx, "81", "45")
	if err != nil || id != "45" || w.writes != 3 {
		t.Fatalf("delete or duplicate writes: %q %v", id, err)
	}
}

func TestCrossSiteWritesRejected(t *testing.T) {
	for _, tc := range []struct{ name, site, record string }{
		{"group", strings.Replace(fixtureSite, "group-a", "group-b", 1), fixtureRecord},
		{"CNAME site", strings.Replace(fixtureSite, `"NS"`, `"CNAME"`, 1), fixtureRecord},
		{"site ID", fixtureSite, strings.Replace(fixtureRecord, "81", "82", 1)},
		{"record ID", fixtureSite, strings.Replace(fixtureRecord, "45", "46", 1)},
		{"record owner", fixtureSite, strings.Replace(fixtureRecord, "www.example.test", "www.another.test", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, w := fixture(t)
			w.site, w.record = tc.site, tc.record
			ctx := context.Background()
			_, err := p.PatchDNSRecord(ctx, "81", "45", dns.RecordPatch{Content: "2001:db8:1::d", TTL: 300})
			_, delErr := p.DeleteDNSRecord(ctx, "81", "45")
			setErr := p.SetBatchAttribute(ctx, "81", "45", "line", "0")
			if !errors.Is(err, domain.ErrRecordNotFound) || !errors.Is(delErr, domain.ErrRecordNotFound) || !errors.Is(setErr, domain.ErrRecordNotFound) || w.writes != 0 {
				t.Fatalf("escaped scope: patch=%v delete=%v metadata=%v writes=%d", err, delErr, setErr, w.writes)
			}
		})
	}
}

func TestMetadataRequiresIntactRecordData(t *testing.T) {
	p, w := fixture(t)
	ctx := context.Background()
	if v, err := p.BatchAttribute(ctx, "81", "45", "line"); v != "1" || err != nil {
		t.Fatal(v, err)
	}
	if v, err := p.BatchAttribute(ctx, "81", "45", "remark"); v != "sample note" || err != nil {
		t.Fatal(v, err)
	}
	w.check = func(action string, q url.Values) {
		if action != "UpdateRecord" {
			return
		}
		if q.Get("Data") != `{"Value":"2001:db8:1::a"}` || q.Has("Ttl") {
			t.Error("metadata update altered record data or TTL")
		}
		if q.Has("Comment") {
			if q.Get("Comment") != "new note" || q.Has("Proxied") {
				t.Error("comment update changed proxy settings")
			}
		} else if q.Get("Proxied") != "true" || q.Get("BizName") != "api" {
			t.Error("line update lost business scenario")
		}
	}
	if err := p.SetBatchAttribute(ctx, "81", "45", "line", "1"); err != nil {
		t.Fatal(err)
	}
	if err := p.SetBatchAttribute(ctx, "81", "45", "remark", "new note"); err != nil {
		t.Fatal(err)
	}
	w.record = strings.Replace(fixtureRecord, `"Value":`, `"Tags":{"sample":"value"},"Value":`, 1)
	err := p.SetBatchAttribute(ctx, "81", "45", "remark", "new note")
	if !errors.Is(err, dns.ErrInvalidDNSRequest) || w.writes != 2 {
		t.Fatal("lossy metadata mutation was accepted")
	}
}

func TestInvalidEndpointAndRecordOwner(t *testing.T) {
	if _, err := New(&domain.Access{Config: map[string]any{"accessKeyId": "sample-id", "accessKeySecret": "sample-key", "region": "test.invalid/"}}); err == nil {
		t.Fatal("invalid region accepted")
	}
	p, w := fixture(t)
	_, err := p.CreateDNSRecord(context.Background(), "81", dns.RecordInput{Name: "www.other.test", Type: "TXT", Content: "sample", TTL: 300})
	if !errors.Is(err, dns.ErrInvalidDNSRequest) || w.writes != 0 {
		t.Fatal("foreign record owner accepted")
	}
}

func TestRecordMetadataOnCreateAndAmbiguousAddressChange(t *testing.T) {
	p, w := fixture(t)
	w.check = func(action string, q url.Values) {
		if action == "CreateRecord" && (q.Get("Comment") != "mail" || q.Get("Data") != `{"Priority":5,"Value":"mail.example.test"}`) {
			t.Fatal("wrong MX data or comment")
		}
	}
	ctx := context.Background()
	priority := 5
	_, err := p.CreateDNSRecord(ctx, "81", dns.RecordInput{Name: "@", Type: "MX", Content: "mail.example.test", TTL: 1, Priority: &priority, Description: "mail"})
	if err != nil {
		t.Fatal(err)
	}
	w.record = strings.Replace(fixtureRecord, "2001:db8:1::a", "127.0.0.1,127.0.0.2", 1)
	_, err = p.PatchDNSRecord(ctx, "81", "45", dns.RecordPatch{Content: "127.0.0.3", TTL: 300})
	if !errors.Is(err, dns.ErrInvalidDNSRequest) || w.writes != 1 {
		t.Fatal("ambiguous multi-address patch changed sibling data")
	}
	w.record = strings.Replace(fixtureRecord, `"Value":"2001:db8:1::a"`, "", 1)
	if err := p.SetBatchAttribute(ctx, "81", "45", "remark", "note"); err == nil || w.writes != 1 {
		t.Fatal("rewrote incomplete RDATA")
	}
}

type failedRequest struct{}

func (failedRequest) Call(r *http.Request, _ *http.Transport) (*http.Response, error) {
	return nil, errors.New("synthetic-sensitive-diagnostic")
}

func TestProviderErrorsAreRedacted(t *testing.T) {
	p, _ := fixture(t)
	p.sdk.HttpClient = failedRequest{}
	if _, err := p.Zones(context.Background(), 1); !errors.Is(err, errProvider) {
		t.Fatal("SDK transport failure escaped the provider boundary")
	}
}

func TestBINDStructuredDataRoundTrip(t *testing.T) {
	srvPriority, srvWeight, mxPriority := 10, 20, 30
	for _, tc := range []struct {
		kind, content, data string
		priority, weight    *int
	}{
		{"CAA", `0 issue "ca.example.test; account=mail ops"`, `{"Flag":0,"Tag":"issue","Value":"ca.example.test; account=mail ops"}`, nil, nil},
		{"SRV", `10 20 443 target.example.test.`, `{"Priority":10,"Weight":20,"Port":443,"Value":"target.example.test."}`, &srvPriority, &srvWeight},
		{"MX", `30 mail.example.test.`, `{"Priority":30,"Value":"mail.example.test."}`, &mxPriority, nil},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			p, w := fixture(t)
			w.record = `{"RecordId":45,"SiteId":81,"RecordName":"service.example.test","RecordType":"` + tc.kind + `","Ttl":300,"Data":` + tc.data + `}`
			w.check = func(action string, q url.Values) {
				if action == "CreateRecord" || action == "UpdateRecord" {
					var got, want map[string]any
					if json.Unmarshal([]byte(tc.data), &want) != nil || json.Unmarshal([]byte(q.Get("Data")), &got) != nil || !reflect.DeepEqual(got, want) {
						t.Error("incorrect provider RDATA")
					}
				}
			}
			ctx := context.Background()
			rows, err := p.DNSRecords(ctx, "81", 2, "")
			if err != nil || len(rows.Items) != 1 || rows.Items[0].Content != tc.content {
				t.Fatal(rows, err)
			}
			r := rows.Items[0]
			_, err = p.CreateDNSRecord(ctx, "81", dns.RecordInput{Name: r.Name, Type: r.Type, Content: r.Content, TTL: r.TTL, Priority: tc.priority, Weight: tc.weight})
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.PatchDNSRecord(ctx, "81", "45", dns.RecordPatch{Content: r.Content, TTL: r.TTL})
			if err != nil || w.writes != 2 {
				t.Fatal(err)
			}
		})
	}
}
