package dnsmcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/apis"

	"github.com/certimate-go/certimate/internal/dnsmcp"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type replacementProvider struct {
	dns.Provider
	record       dns.DNSRecord
	replacements int
	attributes   int
}

func (p *replacementProvider) DNSRecords(_ context.Context, zone string, page int, _ string) (*dns.DNSPage[dns.DNSRecord], error) {
	if zone != "first" || page != 1 {
		return nil, errors.New("unexpected zone or page")
	}
	return &dns.DNSPage[dns.DNSRecord]{Items: []dns.DNSRecord{p.record}, Info: dns.PageInfo{Page: 1, Total: 1}}, nil
}
func (*replacementProvider) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true}
}
func (p *replacementProvider) ReplaceDNSRecord(_ context.Context, zone string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	if zone != "first" || prior.ID != p.record.ID {
		return "", dns.ErrInvalidDNSRequest
	}
	p.replacements++
	p.record.ID = "confirmed-id"
	p.record.Name, p.record.Type, p.record.TTL = desired.Name, desired.Type, desired.TTL
	p.record.Content, p.record.Priority = desired.Content, desired.Priority
	// A transport error after the server accepted a mutation must not replay it.
	return "", errors.New("transport interrupted after delivery")
}
func (*replacementProvider) BatchFields() []string { return []string{"remark"} }
func (p *replacementProvider) BatchAttribute(_ context.Context, zone, id, field string) (string, error) {
	if zone != "first" || field != "remark" || id != p.record.ID {
		return "", dns.ErrInvalidDNSRequest
	}
	return p.record.Description, nil
}
func (p *replacementProvider) SetBatchAttribute(_ context.Context, zone, id, field, value string) error {
	if zone != "first" || field != "remark" || id != p.record.ID {
		return dns.ErrInvalidDNSRequest
	}
	p.attributes++
	p.record.Description = value
	return nil
}

func withReplacementProvider(t *testing.T, record dns.DNSRecord) (*authFixture, *replacementProvider) {
	t.Helper()
	f := setupInterface(t)
	provider := &replacementProvider{record: record}
	r, err := apis.NewRouter(f.app)
	if err != nil {
		t.Fatal(err)
	}
	dnsmcp.Bind(r.RouterGroup, func(_ context.Context, _ string, access string, _ bool) (dns.Provider, error) {
		if access != f.account.Id {
			t.Fatal("resolved ungranted account")
		}
		return provider, nil
	}, dnsmcp.Services{})
	f.mux, err = r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	return f, provider
}

func TestMCPRichEditRecoversIDBeforeMetadataWrite(t *testing.T) {
	f, provider := withReplacementProvider(t, dns.DNSRecord{ID: "prior-id", Name: "old.allowed.example", Type: "CNAME", TTL: 600, Line: "0", Content: "target.example.", Status: "active", Description: "prior description"})
	key := f.issue(t, session(t, f.admin), f.keyInput([]string{"record.update", "record.remark"}, []string{"mcp"}))
	call := func(name string) bool {
		args := fields{"action": "update", "domain_id": f.visible.Id, "recordid": "prior-id", "name": name, "type": "MX", "value": "mail.example.", "mx": 35, "remark": "modified"}
		data := testJSON(t, fields{"id": 1, "jsonrpc": "2.0", "method": "tools/call", "params": fields{"name": "record_manage", "arguments": args}})
		res := f.request("POST", "/mcp", key.bearer(), "application/json", data)
		expectStatus(t, res, 200)
		var got struct {
			Result struct {
				IsError bool `json:"isError"`
				Data    struct {
					ID string `json:"id"`
				} `json:"structuredContent"`
			} `json:"result"`
		}
		readJSON(t, res, &got)
		return !got.Result.IsError && got.Result.Data.ID == "confirmed-id"
	}
	if call("x.hidden.example.") || provider.replacements != 0 {
		t.Fatal("accepted change outside authorized zone")
	}
	if !call("new") || provider.replacements != 1 || provider.attributes != 1 || provider.record.Description != "modified" || provider.record.Priority == nil || *provider.record.Priority != 35 {
		t.Fatalf("replacement or conditional follow-up failed: writes=%d attributes=%d", provider.replacements, provider.attributes)
	}
}

func TestSignedBridgeRichEditUsesNativeSnapshot(t *testing.T) {
	prior := dns.DNSRecord{ID: "prior-id", Name: "old_pause.allowed.example", Type: "A", TTL: 600, Content: "192.0.2.25", Description: "preserve", UpdatedAt: "revision-one"}
	f, provider := withReplacementProvider(t, prior)
	key := f.issue(t, session(t, f.admin), f.keyInput([]string{"domain.read", "record.read", "record.update"}, []string{"api"}))
	list := f.postForm("/api/domain", key.form(time.Now()))
	expectStatus(t, list, 200)
	var domains struct{ Rows []struct{ ID json.Number } }
	readJSON(t, list, &domains)
	if len(domains.Rows) != 1 {
		t.Fatal("expected one authorized domain")
	}
	id := domains.Rows[0].ID.String()
	seq := 0
	post := func(path string, values url.Values, status int) *httptest.ResponseRecorder {
		t.Helper()
		seq++
		r := f.postForm(path, signInterfaceForm(key, path, fmt.Sprintf("%032x", seq), values))
		expectStatus(t, r, status)
		return r
	}
	var details struct {
		Data struct {
			Config struct {
				Edit   dns.RecordEditCapabilities `json:"recordEdit"`
				Native bool                       `json:"nativeRecords"`
			}
		}
	}
	readJSON(t, post("/api/domain/"+id, url.Values{}, 200), &details)
	if !details.Data.Config.Native || details.Data.Config.Edit != provider.RecordEditCapabilities() {
		t.Fatal("signed domain info did not report bridge capabilities")
	}
	records := "/api/record/data/" + id
	get := func(native bool) (*dns.DNSRecord, string) {
		t.Helper()
		form := url.Values{}
		if native {
			form.Set("native_records", "1")
		}
		var out struct {
			Rows []struct {
				Name   string
				Native *dns.DNSRecord
			}
		}
		readJSON(t, post(records, form, 200), &out)
		if len(out.Rows) != 1 {
			t.Fatal("expected one authorized record")
		}
		return out.Rows[0].Native, out.Rows[0].Name
	}
	if row, name := get(false); row != nil || name != "old" {
		t.Fatal("ordinary legacy list changed its response")
	}
	expected, _ := get(true)
	if expected == nil || *expected != prior {
		t.Fatal("native snapshot lost the physical owner or metadata")
	}
	update := "/api/record/update/" + id
	form := func(expected *dns.DNSRecord) url.Values {
		return url.Values{
			"recordid": {expected.ID}, "expected": {testJSON(t, expected)}, "name": {"new_pause.allowed.example"},
			"type": {"A"}, "value": {"192.0.2.26"}, "ttl": {"600"},
		}
	}
	provider.record.UpdatedAt = "revision-two"
	post(update, form(expected), 409)
	if provider.replacements != 0 {
		t.Fatal("signed stale edit reached the provider")
	}
	current, _ := get(true)
	var result struct {
		Code int
		ID   string
	}
	readJSON(t, post(update, form(current), 200), &result)
	if result.Code != 0 || result.ID != "confirmed-id" || provider.replacements != 1 || provider.record.Name != "new_pause.allowed.example" {
		t.Fatal("signed edit lost the physical owner, returned the wrong ID or issued multiple writes")
	}
}
