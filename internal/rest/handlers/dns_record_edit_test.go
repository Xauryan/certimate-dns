package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnsauth"
	_ "github.com/certimate-go/certimate/migrations"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

// This in-memory adapter changes a record's ID on rename and returns fresh
// provider state for every subsequent read, like an ID derived from an RRset.
type nativeEditor struct {
	dns.Provider
	records       map[string]dns.DNSRecord
	reads, writes int
}

func (p *nativeEditor) DNSRecords(_ context.Context, zone string, page int, _ string) (*dns.DNSPage[dns.DNSRecord], error) {
	p.reads++
	row, ok := p.records[zone]
	if !ok || page != 1 {
		return nil, dns.ErrInvalidDNSRequest
	}
	return &dns.DNSPage[dns.DNSRecord]{Items: []dns.DNSRecord{row}, Info: dns.PageInfo{Page: page, Total: 1}}, nil
}

func (p *nativeEditor) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true}
}

func (p *nativeEditor) ReplaceDNSRecord(_ context.Context, zone string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	p.writes++
	row := p.records[zone]
	if row.ID != prior.ID {
		return "", dns.ErrInvalidDNSRequest
	}
	row.ID = "new-record-id"
	row.Type, row.Name, row.Content, row.TTL, row.Priority = desired.Type, desired.Name, desired.Content, desired.TTL, desired.Priority
	row.Line, row.Description, row.Weight = desired.Line, desired.Description, desired.Weight
	p.records[zone] = row
	return row.ID, nil
}

func TestNativeRichEditUsesRenderedSnapshotAndLiveGrant(t *testing.T) {
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.ResetBootstrapState() })
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	type fields = map[string]any
	save := func(collection string, values fields) *core.Record {
		t.Helper()
		c, err := app.FindCollectionByNameOrId(collection)
		if err != nil {
			t.Fatal(err)
		}
		row := core.NewRecord(c)
		for key, value := range values {
			row.Set(key, value)
		}
		if err := app.Save(row); err != nil {
			t.Fatal(err)
		}
		return row
	}
	user := func(collection, email string) (*core.Record, string) {
		t.Helper()
		u := save(collection, fields{"email": email, "password": "synthetic-route-fixture-password"})
		token, err := u.NewAuthToken()
		if err != nil {
			t.Fatal(err)
		}
		return u, token
	}
	editor, editorToken := user(dnsauth.Members, "editor@example.test")
	viewer, viewerToken := user(dnsauth.Members, "viewer@example.test")
	_, adminToken := user(core.CollectionNameSuperusers, "admin@example.test")
	account := save("access", fields{"provider": "cloudflare", "name": "synthetic DNS account"})
	save("dnsAccount", fields{"id": account.Id, "accessRef": account.Id})
	accessible := save("dnsZone", fields{"accountRef": account.Id, "providerZoneId": "first", "name": "one.example", "present": true})
	save("dnsZone", fields{"accountRef": account.Id, "providerZoneId": "second", "name": "two.example", "present": true})
	editGrant := save("dns_zone_grants", fields{"member": editor.Id, "zone": accessible.Id, "role": "editor"})
	save("dns_zone_grants", fields{"member": viewer.Id, "zone": accessible.Id, "role": "reader"})
	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	api := router.Group("/api")
	admin := api.Group("").Bind(apis.RequireSuperuserAuth())
	auth := api.Group("").Bind(apis.RequireAuth(core.CollectionNameSuperusers, dnsauth.Members, dnsauth.ZoneSessions))
	provider := &nativeEditor{records: map[string]dns.DNSRecord{
		"first":  {ID: "current", Name: "before.one.example", Type: "A", Content: "127.0.0.2", TTL: 300, Description: "keep this comment", Line: "default", Status: "enabled"},
		"second": {ID: "foreign", Name: "before.two.example", Type: "A", Content: "127.0.0.3", TTL: 300},
	}}
	calls := 0
	BindDNS(admin, auth, func(_ context.Context, driver, id string, _ bool) (dns.Provider, error) {
		calls++
		if driver != "cloudflare" || id != account.Id {
			t.Fatal("unexpected provider binding")
		}
		return provider, nil
	})
	mux, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	send := func(method, path, token string, body any, wantHTTP, wantCode int) json.RawMessage {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(data))
		req.Header.Set("Authorization", token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != wantHTTP {
			t.Fatalf("%s %s returned HTTP %d, want %d", method, path, rec.Code, wantHTTP)
		}
		if wantHTTP != http.StatusOK {
			return nil
		}
		var out struct {
			Code int
			Data json.RawMessage
		}
		if json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Code != wantCode {
			t.Fatalf("%s %s returned app code %d, want %d", method, path, out.Code, wantCode)
		}
		return out.Data
	}
	send("GET", "/api/dns/providers", editorToken, nil, 403, 0)
	send("GET", "/api/dns/providers", adminToken, nil, 200, 0)
	base := "/api/dns/cloudflare/" + account.Id + "/zones/"
	records := base + "first/records"
	get := func(token string) dns.DNSRecord {
		t.Helper()
		var data struct {
			Items []dns.DNSRecord `json:"result"`
			Edit  dns.RecordEditCapabilities
		}
		if json.Unmarshal(send("GET", records, token, nil, 200, 0), &data) != nil || len(data.Items) != 1 || data.Edit != provider.RecordEditCapabilities() {
			t.Fatal("native listing did not expose this adapter's edit fields and record snapshot")
		}
		return data.Items[0]
	}
	shown := get(editorToken)
	body := fields{"expected": shown, "name": "after.one.example", "type": "MX", "priority": 7, "content": "mail.one.example", "ttl": 600}
	reads, callsBefore := provider.reads, calls
	send("PATCH", records+"/current", viewerToken, body, 200, 403)
	send("PATCH", base+"second/records/foreign", editorToken, body, 200, 404)
	if provider.reads != reads || calls != callsBefore {
		t.Fatal("unauthorized request reached the provider")
	}
	delete(body, "expected")
	send("PATCH", records+"/current", editorToken, body, 200, 400)
	if provider.reads != reads || provider.writes != 0 {
		t.Fatal("rich edit without a snapshot reached the provider")
	}
	body["expected"] = shown
	send("PATCH", records+"/foreign", editorToken, body, 200, 404)
	body["name"] = "after.two.example"
	send("PATCH", records+"/current", editorToken, body, 200, 400)
	body["name"] = "after.one.example"
	changed := provider.records["first"]
	changed.Description = "changed since the listing"
	provider.records["first"] = changed
	send("PATCH", records+"/current", editorToken, body, 200, 409)
	if provider.writes != 0 {
		t.Fatal("a denied or stale edit reached the provider write method")
	}
	body["expected"] = get(editorToken)
	userResult := send("PATCH", records+"/current", editorToken, body, 200, 0)
	var id string
	if json.Unmarshal(userResult, &id) != nil || id != "new-record-id" {
		t.Fatal("route did not return the replacement ID")
	}
	updated := get(editorToken)
	if provider.writes != 1 || updated.ID != id || updated.Name != "after.one.example" || updated.Type != "MX" || updated.Content != "mail.one.example" || updated.TTL != 600 || updated.Priority == nil || *updated.Priority != 7 || updated.Description != changed.Description || updated.Line != changed.Line || updated.Status != changed.Status {
		t.Fatal("successful edit lost metadata, applied incorrect fields, or submitted multiple writes")
	}
	if err := app.Delete(editGrant); err != nil {
		t.Fatal(err)
	}
	body["expected"] = updated
	callsBefore = calls
	send("PATCH", records+"/"+id, editorToken, body, 200, 404)
	if provider.writes != 1 || calls != callsBefore {
		t.Fatal("removed grant permitted another provider operation")
	}
}
