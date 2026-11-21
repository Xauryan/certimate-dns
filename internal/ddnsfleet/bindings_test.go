package ddnsfleet

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnscatalog"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type bindingProvider struct {
	dns.Provider
	records []dns.DNSRecord
	reads   int
	writes  int
	fail    bool
	onRead  func()
}

func (p *bindingProvider) Zones(_ context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	return &dns.DNSPage[dns.Zone]{
		Items: []dns.Zone{{ID: "zone", Name: "example.test"}},
		Info:  dns.PageInfo{Page: page, Total: 1},
	}, nil
}

func (p *bindingProvider) DNSRecords(_ context.Context, zone string, page int, _ string) (*dns.DNSPage[dns.DNSRecord], error) {
	if zone != "zone" || page != 1 {
		return nil, errors.New("unexpected lookup")
	}
	p.reads++
	if p.onRead != nil {
		p.onRead()
	}
	return &dns.DNSPage[dns.DNSRecord]{
		Items: slices.Clone(p.records),
		Info:  dns.PageInfo{Page: page, Total: len(p.records)},
	}, nil
}

func (*bindingProvider) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{}
}

func (p *bindingProvider) ReplaceDNSRecord(_ context.Context, _ string, prior dns.DNSRecord, want dns.RecordInput) (string, error) {
	p.writes++
	if p.fail {
		return "", errors.New("provider failure")
	}
	for i, r := range p.records {
		if r.ID == prior.ID {
			if want.TTL != r.TTL || want.Line != r.Line || want.Description != r.Description || want.Name != r.Name ||
				want.Type != r.Type || want.Weight != r.Weight {
				return "", errors.New("write touched record metadata")
			}
			p.records[i].ID = want.Content
			p.records[i].Content = want.Content
			return want.Content, nil
		}
	}
	return "", errors.New("unexpected record")
}

func TestBindingWorkerVerifiesWritesAndThrottlesIdleAndFailures(t *testing.T) {
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.ResetBootstrapState() })
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}

	p := &bindingProvider{records: []dns.DNSRecord{
		{ID: "anchor", Name: "*.example.test", Type: "A", Content: "192.0.2.4", TTL: 300, Line: "isp", Proxied: true, Description: "keep"},
		{ID: "sibling", Name: "*.example.test", Type: "A", Content: "192.0.2.5", TTL: 300, Line: "isp", Proxied: true},
		{ID: "protected", Name: "other.example.test", Type: "A", Content: "192.0.2.21", TTL: 300, ReadOnly: true},
	}}
	accesses, err := app.FindCollectionByNameOrId("access")
	if err != nil {
		t.Fatal(err)
	}
	createAccount := func(name string) string {
		t.Helper()
		access := core.NewRecord(accesses)
		access.Set("name", name)
		access.Set("provider", "powerdns")
		access.Set("config", map[string]string{"value": "test-only"})
		if err := app.Save(access); err != nil {
			t.Fatal(err)
		}
		discover := func(context.Context, string, string, bool) (dns.Provider, error) { return p, nil }
		if n, err := dnscatalog.ImportZones(t.Context(), app, access.Id, []string{"zone"}, discover); err != nil || n != 1 {
			t.Fatalf("import: %d, %v", n, err)
		}
		return access.Id
	}
	accessA, accessB := createAccount("first"), createAccount("alias")
	for _, nodeID := range []string{"client-a", "client-b"} {
		if _, err := app.DB().Insert("ddns_nodes", dbx.Params{
			"id": nodeID, "name": nodeID, "token_hash": hashToken(nodeID),
		}).Execute(); err != nil {
			t.Fatal(err)
		}
	}
	resolver := func(context.Context, string, string, string) (dns.Provider, error) { return p, nil }
	s := New(resolver)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	report := func(nodeID string, ipv4 ...string) {
		t.Helper()
		snapshot, err := json.Marshal([]Interface{{Name: "eth0", IPv4: ipv4, IPv6: []string{}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := app.DB().Update("ddns_nodes", dbx.Params{
			"seen_at": now.Unix(), "report_required": false, "interfaces": string(snapshot),
		}, dbx.HashExp{"id": nodeID}).Execute(); err != nil {
			t.Fatal(err)
		}
	}
	bound := func() Binding {
		t.Helper()
		rows, err := s.bindings(app)
		if err != nil || len(rows["client-a"]) != 1 {
			t.Fatalf("binding list: %v, %v", rows, err)
		}
		return rows["client-a"][0]
	}
	report("client-a", "192.168.3.4")
	report("client-b", "192.168.3.8")
	input := BindingInput{Provider: "powerdns", AccessID: accessA, ZoneID: "zone", RecordID: "anchor", InterfaceName: "eth0"}
	created, err := s.CreateBinding(t.Context(), app, "client-a", input)
	if err != nil || created.SyncStatus != "pending" || created.RecordName != "*.example.test" || created.RecordType != "A" {
		t.Fatalf("create: %+v, %v", created, err)
	}
	input.AccessID = accessB
	_, err = s.CreateBinding(t.Context(), app, "client-b", input)
	var problem *domain.Error
	if !errors.As(err, &problem) || problem.Code != 409 {
		t.Fatalf("alias credential allowed duplicate writer: %v", err)
	}
	input.RecordID = "protected"
	_, err = s.CreateBinding(t.Context(), app, "client-b", input)
	if !errors.As(err, &problem) || problem.Code != 400 {
		t.Fatalf("protected record was bound: %v", err)
	}

	sync := func() {
		t.Helper()
		if err := s.syncOnlineNodes(t.Context(), app); err != nil {
			t.Fatal(err)
		}
	}
	sync()
	if b := bound(); b.SyncStatus != "synced" || b.RecordID != "192.168.3.4" || b.LastAddress != "192.168.3.4" || p.writes != 1 {
		t.Fatalf("native mutable ID was not adopted: %+v, writes=%d", b, p.writes)
	}
	if p.records[0].TTL != 300 || !p.records[0].Proxied || p.records[0].Line != "isp" || p.records[0].Description != "keep" ||
		p.records[1].Content != "192.0.2.5" {
		t.Fatal("write changed record metadata or siblings")
	}
	reads := p.reads
	for range 4 {
		now = now.Add(15 * time.Second)
		report("client-a", "192.168.3.19", "192.168.3.4")
		sync()
	}
	if p.reads != reads || p.writes != 1 {
		t.Fatal("unchanged address was repeatedly queried or rewritten")
	}
	now = now.Add(reconcileInterval)
	report("client-a", "192.168.3.4")
	sync()
	if p.reads <= reads || p.writes != 1 {
		t.Fatal("periodic reconciliation did not verify unchanged record")
	}

	p.fail = true
	report("client-a", "192.168.3.5")
	sync()
	if b := bound(); b.SyncStatus != "failed" || b.LastError == "" || b.LastAddress != "192.168.3.4" {
		t.Fatalf("failed provider did not preserve the confirmed IP: %+v", b)
	}
	reads = p.reads
	sync()
	if p.reads != reads || p.writes != 2 {
		t.Fatal("provider failure was retried without backoff")
	}
	p.fail = false
	report("client-a", "192.168.3.6")
	sync()
	if b := bound(); b.SyncStatus != "synced" || b.LastAddress != "192.168.3.6" || p.writes != 3 {
		t.Fatalf("new address did not bypass stale retry: %+v", b)
	}

	report("client-a", "192.168.3.7")
	p.onRead = func() {
		p.onRead = nil
		report("client-a", "192.168.3.8")
	}
	sync()
	if p.writes != 3 {
		t.Fatal("superseded report was used for a provider write")
	}
	sync()
	if b := bound(); b.LastAddress != "192.168.3.8" || p.writes != 4 {
		t.Fatalf("newest report did not sync: %+v", b)
	}
	p.records[0].Name = "different.example.test"
	report("client-a", "192.168.3.9")
	sync()
	if b := bound(); b.SyncStatus != "failed" || p.writes != 4 {
		t.Fatalf("record identity drift triggered a write: %+v", b)
	}

	p.records[0].Name = "*.example.test"
	if _, err := app.DB().Update("dnsAccount", dbx.Params{"disabled": true}, dbx.HashExp{"id": accessA}).Execute(); err != nil {
		t.Fatal(err)
	}
	report("client-a", "192.168.3.10")
	reads = p.reads
	sync()
	if b := bound(); b.SyncStatus != "failed" || p.reads != reads {
		t.Fatalf("disabled catalog access attempted a provider call: %+v", b)
	}
	if _, err := app.DB().Update("dnsAccount", dbx.Params{"disabled": false}, dbx.HashExp{"id": accessA}).Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB().Update("ddns_nodes", dbx.Params{"report_required": true}, dbx.HashExp{"id": "client-a"}).Execute(); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	sync()
	if p.reads != reads || p.writes != 4 {
		t.Fatal("a revoked report was used for a provider call")
	}
	report("client-a", "192.168.3.10")
	sync()
	if b := bound(); b.SyncStatus != "synced" || b.LastAddress != "192.168.3.10" || p.writes != 5 {
		t.Fatalf("same-address pending retry did not resume: %+v", b)
	}
	report("client-a")
	sync()
	if b := bound(); b.SyncStatus != "waiting" || b.LastAddress != "192.168.3.10" || p.writes != 5 {
		t.Fatalf("missing address didn't preserve last confirmed record: %+v", b)
	}
	if err := s.DeleteBinding(t.Context(), app, "client-b", created.ID); err == nil {
		t.Fatal("another node was allowed to remove a binding")
	}
	if err := s.DeleteBinding(t.Context(), app, "client-a", created.ID); err != nil {
		t.Fatal(err)
	}
	report("client-a", "192.168.3.11")
	sync()
	if p.writes != 5 {
		t.Fatal("deleted binding still wrote records")
	}
}

func TestDDNSAddressSelection(t *testing.T) {
	iface := &Interface{
		IPv4: []string{"169.254.3.8", "127.0.0.1", "192.168.2.4", "192.168.2.5"},
		IPv6: []string{"fd83::1", "fe80::42", "::ffff:192.168.2.5", "2001:db8::2", "2001:db8::aaff:fe00:3"},
	}
	if got := selectAddress(iface, "A", "192.168.2.5").String(); got != "192.168.2.5" {
		t.Fatalf("private IPv4 preference lost: %s", got)
	}
	if got := selectAddress(iface, "AAAA", "fd83::1", "2001:db8::2").String(); got != "2001:db8::2" {
		t.Fatalf("existing global IPv6 not preserved: %s", got)
	}
	if got := selectAddress(iface, "AAAA").String(); got != "2001:db8::aaff:fe00:3" {
		t.Fatalf("MAC-derived fallback not preferred: %s", got)
	}
	if selectAddress(&Interface{IPv6: iface.IPv6[:3]}, "AAAA").IsValid() {
		t.Fatal("non-global IPv6 selected")
	}
}
