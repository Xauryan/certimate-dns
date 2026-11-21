package ddnsfleet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type bindingRenameProvider struct{ *bindingProvider }

func (*bindingRenameProvider) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true}
}

func (p *bindingRenameProvider) ReplaceDNSRecord(_ context.Context, zone string, prior dns.DNSRecord, want dns.RecordInput) (string, error) {
	if zone != "zone" || want.Content != prior.Content || want.TTL != prior.TTL || want.Type != prior.Type ||
		want.Line != prior.Line || want.Description != prior.Description || want.Priority != prior.Priority || want.Weight != prior.Weight {
		return "", errors.New("rename changed record data")
	}
	for i, r := range p.records {
		if r.ID == prior.ID {
			p.records[i].ID, p.records[i].Name = "renamed-"+prior.ID, want.Name
			p.writes++
			return p.records[i].ID, nil
		}
	}
	return "", errors.New("unexpected record")
}

func TestEditBindingRealHTTP(t *testing.T) {
	app := newBindingTestApp(t)
	p := &bindingRenameProvider{&bindingProvider{records: []dns.DNSRecord{
		{ID: "old", Name: "old.example.test", Type: "A", Content: "10.0.0.4", TTL: 300, Proxied: true, Description: "preserve comment"},
		{ID: "same-family", Name: "old.example.test", Type: "A", Content: "10.0.0.7", TTL: 300},
		{ID: "other-family", Name: "old.example.test", Type: "AAAA", Content: "fd00::a", TTL: 300},
		{ID: "busy", Name: "busy.example.test", Type: "A", Content: "10.0.0.6", TTL: 300},
	}}}
	beforeRecords := slices.Clone(p.records)
	access := newBindingTestAccount(t, app, p, "primary credential")
	s := New(func(context.Context, string, string, string) (dns.Provider, error) { return p, nil })
	admins, err := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		t.Fatal(err)
	}
	admin := core.NewRecord(admins)
	admin.SetEmail("binding-edit@example.test")
	admin.SetPassword("synthetic-binding-edit-password")
	if err := app.Save(admin); err != nil {
		t.Fatal(err)
	}
	adminToken, err := admin.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	s.Bind(router.Group("/api"))
	mux, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	request := func(method, path, token string, body any, want int, result any) {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(method, server.URL+"/api/ddns"+path, bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("%s %s returned %d, want %d", method, path, response.StatusCode, want)
		}
		if result != nil && json.NewDecoder(response.Body).Decode(result) != nil {
			t.Fatal("invalid JSON response")
		}
	}
	node, err := EnrollNode(app, "binding-node")
	if err != nil {
		t.Fatal(err)
	}
	other, err := EnrollNode(app, "other-node")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []IssuedToken{node, other} {
		request(http.MethodPost, "/report", n.Token, report{Hostname: "binding-test", Interfaces: []Interface{
			{Name: "eth0", IPv4: []string{"10.0.0.8"}},
			{Name: "eth1", IPv6: []string{"2001:4860::b"}},
		}}, http.StatusNoContent, nil)
	}
	original := BindingInput{Provider: "powerdns", AccessID: access, ZoneID: "zone", RecordID: "old", InterfaceName: "eth0"}
	bound, err := s.CreateBinding(t.Context(), app, node.ID, original)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB().Update("ddns_bindings", dbx.Params{
		"last_address": "10.0.0.8", "sync_status": "failed", "last_error": "previous error",
		"attempted_address": "10.0.0.9", "failure_count": 3, "updated_at": "2025-01-01T00:00:00Z",
	}, dbx.HashExp{"id": bound.ID}).Execute(); err != nil {
		t.Fatal(err)
	}
	stored := func() Binding {
		t.Helper()
		var b Binding
		if err := app.DB().Select("*").From("ddns_bindings").Where(dbx.HashExp{"id": bound.ID}).One(&b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	initial := stored()
	path := "/nodes/" + node.ID + "/bindings/" + bound.ID
	edit := bindingEditInput{
		RecordName: "new", InterfaceName: "eth1",
		ExpectedRecordName: bound.RecordName, ExpectedInterfaceName: bound.InterfaceName,
	}
	request(http.MethodPut, path, "", edit, http.StatusUnauthorized, nil)
	request(http.MethodPut, path, node.Token, edit, http.StatusUnauthorized, nil)
	request(http.MethodPut, "/nodes/"+other.ID+"/bindings/"+bound.ID, adminToken, edit, http.StatusNotFound, nil)
	request(http.MethodPut, path+"missing", adminToken, edit, http.StatusNotFound, nil)
	invalid := edit
	invalid.RecordName = "outside.test"
	request(http.MethodPut, path, adminToken, invalid, http.StatusBadRequest, nil)
	invalid = edit
	invalid.InterfaceName = "missing"
	request(http.MethodPut, path, adminToken, invalid, http.StatusBadRequest, nil)
	invalid = edit
	invalid.ExpectedRecordName = "stale"
	request(http.MethodPut, path, adminToken, invalid, http.StatusConflict, nil)
	invalid = edit
	invalid.ExpectedInterfaceName = "eth1"
	request(http.MethodPut, path, adminToken, invalid, http.StatusConflict, nil)
	invalid = edit
	invalid.RecordName = "busy"
	request(http.MethodPut, path, adminToken, invalid, http.StatusConflict, nil)
	if got := stored(); got != initial {
		t.Fatalf("rejected edit modified the binding: %+v", got)
	}
	assertProvider := func(writes int, records []dns.DNSRecord) {
		t.Helper()
		s.mutations.Lock()
		defer s.mutations.Unlock()
		if p.writes != writes || !slices.Equal(p.records, records) {
			t.Fatal("binding edit changed unexpected provider records")
		}
	}
	assertProvider(0, beforeRecords)
	var edited Binding
	request(http.MethodPut, path, adminToken, edit, http.StatusOK, &edited)
	if edited.ID != bound.ID || edited.ZoneName != "example.test" || edited.RecordID != "renamed-old" ||
		edited.RecordName != "new.example.test" || edited.RecordType != "A" || edited.InterfaceName != "eth1" {
		t.Fatalf("edit did not retain the binding ID and adopt the verified DNS record: %+v", edited)
	}
	changed := stored()
	if changed.SyncStatus != "pending" || changed.LastAddress != "" || changed.LastError != "" ||
		changed.AttemptedAddress != "" || changed.FailureCount != 0 || changed.UpdatedAt == initial.UpdatedAt {
		t.Fatalf("interface change carried over the previous synchronization state: %+v", changed)
	}
	var retried Binding
	request(http.MethodPut, path, adminToken, edit, http.StatusOK, &retried)
	if retried != edited || stored() != changed {
		t.Fatal("retry of the fulfilled edit changed the binding")
	}
	beforeRecords[0].ID, beforeRecords[0].Name = "renamed-old", "new.example.test"
	assertProvider(1, beforeRecords)

	ifaceOnly := bindingEditInput{
		RecordName: edited.RecordName, InterfaceName: "eth0",
		ExpectedRecordName: edited.RecordName, ExpectedInterfaceName: edited.InterfaceName,
	}
	var switched Binding
	request(http.MethodPut, path, adminToken, ifaceOnly, http.StatusOK, &switched)
	if switched.ID != edited.ID || switched.RecordID != edited.RecordID || switched.RecordName != edited.RecordName ||
		switched.InterfaceName != ifaceOnly.InterfaceName {
		t.Fatalf("interface edit changed the DNS record identity: %+v", switched)
	}
	changed = stored()
	assertProvider(1, beforeRecords)

	if _, err := app.DB().Insert("ddns_binding_renames", dbx.Params{
		"binding_id": bound.ID, "target_name": "busy.example.test", "interface_name": "eth1",
		"source_snapshot": "{}", "submitted": true, "created_at": "2025-01-01T00:00:00Z",
		"candidate_id": "candidate-for-review",
	}).Execute(); err != nil {
		t.Fatal(err)
	}
	var inventory []NodeView
	request(http.MethodGet, "/nodes", adminToken, nil, http.StatusOK, &inventory)
	if len(inventory) != 2 || inventory[0].ID != node.ID || len(inventory[0].Bindings) != 1 {
		t.Fatalf("missing the existing binding from the node inventory")
	}
	pending := inventory[0].Bindings[0].PendingRename
	if pending == nil || pending.RecordName != "busy.example.test" || pending.InterfaceName != "eth1" ||
		!pending.Submitted || pending.CandidateRecordID != "candidate-for-review" {
		t.Fatal("the node inventory did not advertise the pending rename")
	}
	request(http.MethodPost, "/report", node.Token, report{Hostname: "binding-test", Interfaces: []Interface{
		{Name: "eth0", IPv4: []string{"10.0.0.8"}},
	}}, http.StatusNoContent, nil)
	recheck := bindingEditInput{
		RecordName: pending.RecordName, InterfaceName: pending.InterfaceName,
		ExpectedRecordName: changed.RecordName, ExpectedInterfaceName: changed.InterfaceName,
	}
	request(http.MethodPut, path, adminToken, recheck, http.StatusConflict, nil)
	request(http.MethodDelete, path, adminToken, nil, http.StatusConflict, nil)
	request(http.MethodDelete, "/nodes/"+node.ID, adminToken, nil, http.StatusConflict, nil)
	original.RecordID = "busy"
	request(http.MethodPost, "/nodes/"+other.ID+"/bindings", adminToken, original, http.StatusConflict, nil)
	confirm := map[string]string{"recordId": "different-record"}
	request(http.MethodPost, path+"/rename/confirm", node.Token, confirm, http.StatusUnauthorized, nil)
	request(http.MethodPost, path+"/rename/confirm", adminToken, confirm, http.StatusConflict, nil)
	if stored() != changed {
		t.Fatal("submitted rename lost its bound record")
	}
	assertProvider(1, beforeRecords)

	if _, err := app.DB().Update("ddns_binding_renames", dbx.Params{
		"submitted": false, "candidate_id": "",
	}, dbx.HashExp{"binding_id": bound.ID}).Execute(); err != nil {
		t.Fatal(err)
	}
	request(http.MethodDelete, path+"/rename", node.Token, nil, http.StatusUnauthorized, nil)
	var cancelled Binding
	request(http.MethodDelete, path+"/rename", adminToken, nil, http.StatusOK, &cancelled)
	if cancelled.ID != bound.ID || cancelled.RecordID != changed.RecordID || cancelled.PendingRename != nil || stored() != changed {
		t.Fatal("cancelling the prepared rename changed the binding")
	}
	inventory = nil
	request(http.MethodGet, "/nodes", adminToken, nil, http.StatusOK, &inventory)
	if inventory[0].Bindings[0].PendingRename != nil {
		t.Fatal("cancelled rename was still advertised")
	}
	assertProvider(1, beforeRecords)
}

func TestBindingEditOwnerStaysInZone(t *testing.T) {
	for raw, want := range map[string]string{
		"@": "example.test", "*": "*.example.test", "Next": "next.example.test",
		"Next.Sub.Example.Test.": "next.sub.example.test",
		"*.sub.example.test":     "*.sub.example.test",
	} {
		if got, err := bindingOwner(raw, "example.test"); err != nil || got != want {
			t.Errorf("owner %q: got %q, %v; wanted %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"host.other.test", "host.other.test.", "example.tests", "*.*.example.test", "example..test"} {
		if _, err := bindingOwner(raw, "example.test"); err == nil {
			t.Errorf("accepted invalid or outside-zone DNS name %q", raw)
		}
	}
}
