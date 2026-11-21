package ddnsfleet

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type renameProvider struct {
	bindingProvider
	changeID       bool
	loseReply      bool
	blockReadAfter bool
	readBlocked    bool
	reject         error
}

func (p *renameProvider) DNSRecords(ctx context.Context, zone string, page int, name string) (*dns.DNSPage[dns.DNSRecord], error) {
	if p.readBlocked {
		return nil, errors.New("synthetic provider read outage")
	}
	return p.bindingProvider.DNSRecords(ctx, zone, page, name)
}

func (*renameProvider) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true}
}

func (p *renameProvider) ReplaceDNSRecord(_ context.Context, _ string, prior dns.DNSRecord, want dns.RecordInput) (string, error) {
	p.writes++
	if p.reject != nil {
		return "", p.reject
	}
	for i := range p.records {
		r := &p.records[i]
		if r.ID != prior.ID {
			continue
		}
		if want.Type != r.Type || want.Content != r.Content || want.TTL != r.TTL ||
			want.Line != r.Line || want.Description != r.Description || !reflect.DeepEqual(want.Weight, r.Weight) {
			return "", errors.New("rename attempted to change record attributes")
		}
		r.Name = want.Name
		if p.changeID {
			r.ID = "new-provider-id"
		}
		if p.blockReadAfter {
			p.readBlocked = true
		}
		if p.loseReply {
			return "", errors.New("synthetic lost provider response")
		}
		return r.ID, nil
	}
	return "", errors.New("record not found")
}

type bindingRenameFixture struct {
	service *Service
	app     core.App
	binding Binding
	p       *renameProvider
}

func newBindingRenameFixture(t *testing.T) bindingRenameFixture {
	t.Helper()
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.ResetBootstrapState() })
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	if _, err := app.DB().Insert("ddns_nodes", dbx.Params{
		"id": "client", "name": "client", "token_hash": hashToken("synthetic-device"),
		"seen_at": now.Unix(), "report_required": false,
		"interfaces": `[{"name":"eth0","mac":"","ipv4":["192.0.2.5"],"ipv6":[]}]`,
	}).Execute(); err != nil {
		t.Fatal(err)
	}
	b := Binding{
		ID: "rename-binding", NodeID: "client", Provider: "powerdns", AccessID: "test-credential",
		ZoneID: "zone", ZoneName: "example.test", RecordID: "old-provider-id", RecordName: "old.example.test",
		RecordType: "A", InterfaceName: "eth0", LastAddress: "192.0.2.4", SyncStatus: "synced",
		UpdatedAt: now.Format(time.RFC3339),
	}
	if _, err := app.DB().Insert("ddns_bindings", dbx.Params{
		"id": b.ID, "node_id": b.NodeID, "provider": b.Provider, "access_id": b.AccessID,
		"zone_id": b.ZoneID, "zone_name": b.ZoneName, "record_id": b.RecordID, "record_name": b.RecordName,
		"record_type": b.RecordType, "interface_name": b.InterfaceName, "last_address": b.LastAddress,
		"sync_status": b.SyncStatus, "updated_at": b.UpdatedAt,
	}).Execute(); err != nil {
		t.Fatal(err)
	}
	weight := 7
	provider := &renameProvider{bindingProvider: bindingProvider{records: []dns.DNSRecord{
		{ID: b.RecordID, Name: b.RecordName, Type: b.RecordType, Content: b.LastAddress, TTL: 300,
			Line: "regional", Description: "preserve", Weight: &weight, Status: "disabled", Proxied: true},
		{ID: "source-sibling", Name: b.RecordName, Type: "A", Content: "192.0.2.5", TTL: 300, Line: "regional"},
		{ID: "target-sibling", Name: "renamed.example.test", Type: "TXT", Content: "preserve other record type", TTL: 60},
	}}}
	service := New(func(context.Context, string, string, string) (dns.Provider, error) { return provider, nil })
	service.now = func() time.Time { return now }
	return bindingRenameFixture{service: service, app: app, binding: b, p: provider}
}

func (f bindingRenameFixture) rename(t *testing.T, b Binding, target, iface string) (Binding, error) {
	t.Helper()
	f.service.mutations.Lock()
	defer f.service.mutations.Unlock()
	return f.service.renameBindingRecord(t.Context(), f.app, f.p, b, target, iface, func() bool { return true })
}

func (f bindingRenameFixture) bound(t *testing.T) Binding {
	t.Helper()
	var b Binding
	if err := f.app.DB().Select("*").From("ddns_bindings").Where(dbx.HashExp{"id": f.binding.ID}).One(&b); err != nil {
		t.Fatalf("could not read binding: %v", err)
	}
	return b
}

func assertRenameConflict(t *testing.T, err error) {
	t.Helper()
	var problem *domain.Error
	if !errors.As(err, &problem) || problem.Code != http.StatusConflict {
		t.Fatalf("expected a rename conflict, got %v", err)
	}
}

func TestBindingRenamePreservesMetadataAndAdoptsProviderID(t *testing.T) {
	f := newBindingRenameFixture(t)
	f.p.changeID = true
	b, err := f.rename(t, f.binding, "renamed.example.test", "eth0")
	if err != nil || b.RecordID != "new-provider-id" || b.RecordName != "renamed.example.test" ||
		b.InterfaceName != "eth0" || b.LastAddress != f.binding.LastAddress || b.SyncStatus != "pending" || f.p.writes != 1 {
		t.Fatalf("rename: %+v, %v, writes=%d", b, err, f.p.writes)
	}
	if actual := f.bound(t); actual != b {
		t.Fatalf("persisted binding differs: %+v", actual)
	}
	r := f.p.records[0]
	if r.Content != "192.0.2.4" || r.TTL != 300 || r.Line != "regional" || r.Description != "preserve" ||
		!r.Proxied || r.Status != "disabled" || r.Weight == nil || *r.Weight != 7 ||
		f.p.records[1].Name != f.binding.RecordName || f.p.records[2].Content != "preserve other record type" {
		t.Fatal("provider rename changed other record attributes or siblings")
	}
	reads := f.p.reads
	again, err := f.rename(t, b, b.RecordName, b.InterfaceName)
	if err != nil || again != b || f.p.writes != 1 || f.p.reads != reads {
		t.Fatalf("same desired rename was not a no-op: %+v, %v", again, err)
	}
}

func TestBindingRenameRecoversWithoutRepeatingProviderWrite(t *testing.T) {
	t.Run("provider receipt stored before read outage", func(t *testing.T) {
		f := newBindingRenameFixture(t)
		f.p.changeID, f.p.blockReadAfter = true, true
		_, err := f.rename(t, f.binding, "renamed.example.test", "eth1")
		assertRenameConflict(t, err)
		if old := f.bound(t); old != f.binding || f.p.writes != 1 {
			t.Fatalf("unconfirmed remote result changed binding: %+v", old)
		}
		f.p.readBlocked = false
		if err := f.service.syncOnlineNodes(t.Context(), f.app); err != nil {
			t.Fatal(err)
		}
		if current := f.bound(t); current != f.binding || f.p.writes != 1 {
			t.Fatalf("worker ignored pending rename: %+v, writes=%d", current, f.p.writes)
		}
		_, err = f.rename(t, f.binding, "other.example.test", "eth1")
		assertRenameConflict(t, err)

		f.service = New(nil)
		recovered, err := f.rename(t, f.binding, "renamed.example.test", "eth1")
		if err != nil || recovered.RecordID != "new-provider-id" ||
			recovered.RecordName != "renamed.example.test" || recovered.InterfaceName != "eth1" ||
			recovered.LastAddress != "" || recovered.SyncStatus != "pending" || f.p.writes != 1 {
			t.Fatalf("could not recover persisted receipt: %+v, %v", recovered, err)
		}
	})
	t.Run("database commit failure", func(t *testing.T) {
		f := newBindingRenameFixture(t)
		f.p.changeID = true
		if _, err := f.app.DB().NewQuery(`CREATE TRIGGER reject_binding_rename BEFORE UPDATE OF record_name ON ddns_bindings
			BEGIN SELECT RAISE(ABORT, 'synthetic write barrier'); END`).Execute(); err != nil {
			t.Fatal(err)
		}
		_, err := f.rename(t, f.binding, "renamed.example.test", "eth0")
		assertRenameConflict(t, err)
		if current := f.bound(t); current != f.binding || f.p.writes != 1 {
			t.Fatalf("failed local transaction did not preserve existing binding: %+v", current)
		}
		if _, err := f.app.DB().NewQuery("DROP TRIGGER reject_binding_rename").Execute(); err != nil {
			t.Fatal(err)
		}
		b, err := f.rename(t, f.binding, "renamed.example.test", "eth0")
		if err != nil || b.RecordID != "new-provider-id" || f.p.writes != 1 {
			t.Fatalf("local recovery rewrote provider record: %+v, %v, writes=%d", b, err, f.p.writes)
		}
	})
	t.Run("lost reply with stable ID", func(t *testing.T) {
		f := newBindingRenameFixture(t)
		f.p.loseReply = true
		b, err := f.rename(t, f.binding, "renamed.example.test", "eth0")
		if err != nil || b.RecordID != f.binding.RecordID || b.RecordName != "renamed.example.test" || f.p.writes != 1 {
			t.Fatalf("stable ID could not verify lost response: %+v, %v", b, err)
		}
	})
	t.Run("same address is insufficient without a new ID receipt", func(t *testing.T) {
		f := newBindingRenameFixture(t)
		f.p.changeID, f.p.loseReply = true, true
		for range 2 {
			_, err := f.rename(t, f.binding, "renamed.example.test", "eth0")
			assertRenameConflict(t, err)
		}
		if current := f.bound(t); current != f.binding || f.p.writes != 1 {
			t.Fatalf("guessed a replacement record or repeated provider write: %+v, writes=%d", current, f.p.writes)
		}
		intent, err := loadBindingRename(t.Context(), f.app, f.binding.ID)
		if err != nil || intent.CandidateID != "new-provider-id" {
			t.Fatalf("matching replacement not offered for explicit confirmation: %+v, %v", intent, err)
		}
		authorize := func() bool { return true }
		f.service.mutations.Lock()
		defer f.service.mutations.Unlock()
		_, err = f.service.confirmBindingRename(t.Context(), f.app, f.p, f.binding, "other-id", authorize)
		assertRenameConflict(t, err)
		f.p.records[1].TTL++
		_, err = f.service.confirmBindingRename(t.Context(), f.app, f.p, f.binding, intent.CandidateID, authorize)
		assertRenameConflict(t, err)
		f.p.records[1].TTL--
		confirmed, err := f.service.confirmBindingRename(t.Context(), f.app, f.p, f.binding, intent.CandidateID, authorize)
		if err != nil || confirmed.RecordID != intent.CandidateID || f.p.writes != 1 {
			t.Fatalf("could not confirm a uniquely matching replacement: %+v, %v, writes=%d", confirmed, err, f.p.writes)
		}
	})
}

func TestBindingRenameRejectsOccupiedDestinationWithoutWrite(t *testing.T) {
	f := newBindingRenameFixture(t)
	f.p.records = append(f.p.records, dns.DNSRecord{
		ID: "existing-target", Name: "renamed.example.test", Type: "A", Content: "192.0.2.60", TTL: 300, Line: "another-line",
	})
	_, err := f.rename(t, f.binding, "renamed.example.test", "eth0")
	assertRenameConflict(t, err)
	if f.p.writes != 0 {
		t.Fatal("rename overwrote an existing same-type record through another line")
	}
	f.p.records = f.p.records[:len(f.p.records)-1]
	if _, err := f.rename(t, f.binding, "renamed.example.test", "eth0"); err != nil || f.p.writes != 1 {
		t.Fatalf("confirmed pre-write failure could not be retried: %v, writes=%d", err, f.p.writes)
	}
}

func TestBindingRenameRejectedOrCancelledWithIntactSource(t *testing.T) {
	t.Run("definitive input rejection resumes original binding", func(t *testing.T) {
		f := newBindingRenameFixture(t)
		f.p.reject = dns.ErrInvalidDNSRequest
		_, err := f.rename(t, f.binding, "renamed.example.test", "eth0")
		var problem *domain.Error
		if !errors.As(err, &problem) || problem.Code != http.StatusUnprocessableEntity {
			t.Fatalf("expected provider rejection, got %v", err)
		}
		if pending, err := hasBindingRename(t.Context(), f.app, f.binding.ID); pending || err != nil {
			t.Fatalf("unchanged source remained fenced: %v, %v", pending, err)
		}
		f.p.reject = nil
		if b, err := f.rename(t, f.binding, "renamed.example.test", "eth0"); err != nil || b.RecordName != "renamed.example.test" {
			t.Fatalf("could not retry after provider validation failure: %+v, %v", b, err)
		}
	})
	t.Run("uncertain rejection needs explicit cancellation and intact evidence", func(t *testing.T) {
		f := newBindingRenameFixture(t)
		f.p.reject = errors.New("synthetic ambiguous submission failure")
		_, err := f.rename(t, f.binding, "renamed.example.test", "eth0")
		assertRenameConflict(t, err)
		_, err = f.rename(t, f.binding, "renamed.example.test", "eth0")
		assertRenameConflict(t, err)
		if f.p.writes != 1 {
			t.Fatal("uncertain provider submission was repeated")
		}
		cancel := func() (Binding, error) {
			f.service.mutations.Lock()
			defer f.service.mutations.Unlock()
			return f.service.cancelBindingRename(t.Context(), f.app, f.p, f.binding, func() bool { return true })
		}
		_, err = cancel()
		assertRenameConflict(t, err)
		later := f.service.now().Add(renameCancelDelay + time.Second)
		f.service.now = func() time.Time { return later }
		f.p.records[1].TTL++
		_, err = cancel()
		assertRenameConflict(t, err)
		f.p.records[1].TTL--
		current, err := cancel()
		if err != nil || current != f.binding || f.p.writes != 1 {
			t.Fatalf("could not cancel verified unchanged source: %+v, %v", current, err)
		}
		if pending, err := hasBindingRename(t.Context(), f.app, f.binding.ID); pending || err != nil {
			t.Fatalf("cancellation did not release fence: %v, %v", pending, err)
		}
	})
}
