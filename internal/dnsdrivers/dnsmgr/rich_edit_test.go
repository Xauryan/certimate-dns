package dnsmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	u "github.com/certimate-go/certimate/internal/dnsdrivers/selfhostutil"
	"github.com/certimate-go/certimate/internal/dnssign"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestDelegatedRichEdit(t *testing.T) {
	config := `{"type":"powerdns"}`
	writes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/domain/1":
			fmt.Fprintf(w, `{"code":0,"data":{"id":1,"name":"example.test","config":%s}}`, config)
		case "/api/record/data/1":
			fmt.Fprint(w, `[{"RecordID":"a","Name":"www","Domain":"example.test","Value":"text","Type":"TXT","TTL":"120","Line":"edge","Weight":4,"Remark":"keep"}]`)
		case "/api/record/update/1":
			writes++
			r.ParseForm()
			if r.FormValue("recordid") != "a" || r.FormValue("name") != "mail" || r.FormValue("mx") != "8" || r.FormValue("type") != "MX" || r.FormValue("line") != "edge" || r.FormValue("remark") != "keep" || r.FormValue("weight") != "4" {
				t.Error("incorrect replacement fields")
			}
			fmt.Fprint(w, `{"code":0,"id":"new-id"}`)
		default:
			t.Error("unexpected request", r.URL.Path)
		}
	}))
	defer srv.Close()
	client, _ := u.NewClient(srv.URL)
	p := &provider{client: client, uid: "2", key: "synthetic", signatureMode: "v2"}
	ctx := t.Context()
	page, err := p.DNSRecords(ctx, "1", 1, "")
	if err != nil || len(page.Items) != 1 {
		t.Fatal(page, err)
	}
	old := page.Items[0]
	priority := 8
	in := dns.RecordInput{Name: "mail.example.test", Type: "MX", Content: "mx.example.test", TTL: 180, Priority: &priority, Line: old.Line, Description: old.Description, Weight: old.Weight}
	if caps, err := p.ZoneRecordEditCapabilities(ctx, "1"); err != nil || caps != (dns.RecordEditCapabilities{}) {
		t.Fatal(caps, err)
	}
	if _, err := p.ReplaceDNSRecord(ctx, "1", old, in); err == nil {
		t.Fatal("unsafe legacy backend move")
	}
	config = `{"type":"goedge"}`
	if id, err := p.ReplaceDNSRecord(ctx, "1", old, in); err != nil || id != "a" {
		t.Fatal(id, err)
	}
	config = `{"type":"powerdns","recordEdit":{"rename":true,"retype":true,"priority":true}}`
	if id, err := p.ReplaceDNSRecord(ctx, "1", old, in); err != nil || id != "new-id" {
		t.Fatal(id, err)
	}
	config = `{"type":"powerdns","recordEdit":{"rename":false,"retype":true,"priority":true}}`
	if _, err := p.ReplaceDNSRecord(ctx, "1", old, in); err == nil {
		t.Fatal("ignored upstream restriction")
	}
	if writes != 2 {
		t.Fatal(writes)
	}
}

func TestNativeRecordSnapshotsAndConditionalV2Edit(t *testing.T) {
	const key = "synthetic"
	const zid = "17"
	backend := dns.DNSRecord{ID: "a", Name: "hidden_pause.example.test", Type: "A", TTL: 300, Content: "192.0.2.1", Description: "keep", Status: "paused", Proxied: true, UpdatedAt: "2025-01-01T00:00:00Z"}
	writes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.ParseForm() != nil || r.PostForm.Get("sign_version") != "2" || dnssign.Sign(r.URL.Path, r.PostForm, key) != r.PostForm.Get("sign") {
			t.Error("invalid signed bridge request")
			w.WriteHeader(400)
			return
		}
		switch r.URL.Path {
		case "/api/domain/" + zid:
			fmt.Fprint(w, `{"code":0,"data":{"id":17,"name":"example.test","config":{"type":"cloudflare","nativeRecords":true,"recordEdit":{"rename":true,"retype":true,"priority":true}}}}`)
		case "/api/record/data/" + zid:
			if r.PostForm.Get("native_records") != "1" {
				t.Error("did not opt in to native record reads")
			}
			fmt.Fprint(w, `{"total":1,"rows":[{"RecordId":"a","Name":"hidden","Domain":"example.test","Value":"192.0.2.1","Type":"A","TTL":300,"Line":"1","Status":"0","Native":`)
			_ = json.NewEncoder(w).Encode(backend)
			fmt.Fprint(w, `}]}`)
		case "/api/record/update/" + zid:
			writes++
			var expected dns.DNSRecord
			if err := json.Unmarshal([]byte(r.PostForm.Get("expected")), &expected); err != nil || !reflect.DeepEqual(expected, backend) {
				t.Error("did not forward the canonical expected snapshot", err)
			}
			if r.PostForm.Get("name") != "renamed_pause" || r.PostForm.Get("recordid") != "a" || r.PostForm.Has("line") || r.PostForm.Has("remark") || r.PostForm.Has("weight") {
				t.Error("did not preserve remote metadata")
			}
			fmt.Fprint(w, `{"code":0,"id":"replacement"}`)
		default:
			t.Error("unexpected bridge request", r.URL.Path)
		}
	}))
	defer srv.Close()
	client, _ := u.NewClient(srv.URL)
	p := &provider{client: client, uid: "2", key: key, signatureMode: "v2"}
	ctx := context.Background()
	rows, err := p.DNSRecords(ctx, zid, 1, "")
	if err != nil || len(rows.Items) != 1 || !reflect.DeepEqual(rows.Items[0], backend) {
		t.Fatal(rows, err)
	}
	prior := rows.Items[0]
	desired := dns.RecordInput{Name: "renamed_pause.example.test", Type: prior.Type, Content: prior.Content, TTL: prior.TTL, Description: prior.Description}
	backend.UpdatedAt = "2025-01-01T00:00:01Z"
	if _, err = p.ReplaceDNSRecord(ctx, zid, prior, desired); err == nil || writes != 0 {
		t.Fatal("accepted a stale revision", err)
	}
	prior.UpdatedAt = backend.UpdatedAt
	if id, err := p.ReplaceDNSRecord(ctx, zid, prior, desired); err != nil || id != "replacement" || writes != 1 {
		t.Fatal(id, err, writes)
	}
}

func TestLegacyBaotaRecordDoesNotExposeMXPreferenceAsWeight(t *testing.T) {
	z := zone{Name: "example.test"}
	z.Config.Type = "bt"
	row := record{RecordID: "1", Name: "mail", Type: "MX", Value: "exchange.test.", TTL: "300", MX: "10", Weight: "10"}
	got, err := row.dns(z)
	if err != nil || got.Weight != nil || got.Priority == nil || *got.Priority != 10 {
		t.Fatal(got, err)
	}
	row.Type = "A"
	got, err = row.dns(z)
	if err != nil || got.Weight == nil || *got.Weight != 10 || got.Priority != nil {
		t.Fatal(got, err)
	}
}
