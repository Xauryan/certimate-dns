package dnsmcp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pocketbase/pocketbase/apis"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsmgr"
	"github.com/certimate-go/certimate/internal/dnsmcp"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestSignedDNSMgrBridgeEditsCanonicalPausedOwner(t *testing.T) {
	f := setupInterface(t)
	backend := &replacementProvider{record: dns.DNSRecord{
		ID: "prior-id", Name: "old_pause.allowed.example", Type: "CNAME", Content: "target.example.",
		TTL: 600, Line: "0", Status: "disabled", Description: "keep", UpdatedAt: "2026-01-02T03:04:05Z",
	}}
	router, err := apis.NewRouter(f.app)
	if err != nil {
		t.Fatal(err)
	}
	dnsmcp.Bind(router.RouterGroup, func(_ context.Context, _ string, id string, _ bool) (dns.Provider, error) {
		if id != f.account.Id {
			return nil, domain.ErrRecordNotFound
		}
		return backend, nil
	}, dnsmcp.Services{})
	f.mux, err = router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	key := f.issue(t, session(t, f.admin), f.keyInput([]string{"domain.read", "record.read", "record.update"}, []string{"api"}))
	var concurrent atomic.Bool
	var requests sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Lock()
		defer requests.Unlock()
		if strings.HasPrefix(r.URL.Path, "/api/record/update/") && concurrent.CompareAndSwap(true, false) {
			backend.record.UpdatedAt = "2026-01-02T03:04:06Z"
		}
		f.mux.ServeHTTP(w, r)
	}))
	defer server.Close()
	bridge, err := dnsmgr.New(&domain.Access{Config: fields{"uid": key.UID, "apiKey": key.APIKey, "serverUrl": server.URL, "signatureMode": "v2"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	zones, err := bridge.Zones(ctx, 1)
	if err != nil || len(zones.Items) != 1 || zones.Items[0].Name != "allowed.example" {
		t.Fatal(zones, err)
	}
	zid := zones.Items[0].ID
	prior, err := bridge.DNSRecords(ctx, zid, 1, "")
	if err != nil || len(prior.Items) != 1 || prior.Items[0].Name != "old_pause.allowed.example" || prior.Items[0].Status != "disabled" {
		t.Fatal(prior, err)
	}
	editor := bridge.(dns.RecordEditor)
	want := dns.RecordInput{Name: "new_pause.allowed.example", Type: "CNAME", Content: "target.example.", TTL: 600, Line: "0", Description: "keep"}
	concurrent.Store(true)
	if _, err := editor.ReplaceDNSRecord(ctx, zid, prior.Items[0], want); err == nil {
		t.Fatal("relay overwrote a newer remote record")
	}
	prior, err = bridge.DNSRecords(ctx, zid, 1, "")
	if err != nil || len(prior.Items) != 1 || prior.Items[0].Name != "old_pause.allowed.example" {
		t.Fatal(prior, err)
	}
	id, err := editor.ReplaceDNSRecord(ctx, zid, prior.Items[0], want)
	if err != nil || id != "confirmed-id" {
		t.Fatal(id, err)
	}
	updated, err := bridge.DNSRecords(ctx, zid, 1, "")
	if err != nil || len(updated.Items) != 1 || updated.Items[0].Name != want.Name || updated.Items[0].Status != "disabled" || updated.Items[0].Description != want.Description {
		t.Fatal(updated, err)
	}
}
