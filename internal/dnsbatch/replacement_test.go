package dnsbatch

import (
	"context"
	"errors"
	"strings"
	"testing"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	"github.com/pocketbase/dbx"
)

type replacementProvider struct {
	attributedProvider
	loseGroup bool
}

func (*replacementProvider) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true}
}

func (p *replacementProvider) ReplaceDNSRecord(_ context.Context, zone string, prior dns.DNSRecord, want dns.RecordInput) (string, error) {
	row := byID(p.rows, prior.ID)
	if zone != "upstream" || row == nil || digest(*row) != digest(prior) || want.Line != row.Line || want.Description != row.Description {
		return "", errors.New("incorrect source record or replacement metadata")
	}
	p.writes++
	*row = replacementRecord(*row, want)
	row.ID = "replaced-" + prior.ID
	if p.loseGroup {
		p.group = ""
	}
	return row.ID, nil
}

func TestReplacementReconcilesNewIDWithoutReplay(t *testing.T) {
	db := testApp(t).DB()
	zero := 0
	old := dns.DNSRecord{ID: "old", Name: "mail." + origin, Type: "MX", Content: "15 smtp." + origin, TTL: 300, Description: "synthetic comment", Status: "disabled", Line: "telecom"}
	sibling := dns.DNSRecord{ID: "sibling", Name: "mail." + origin, Type: "TXT", Content: "synthetic sibling", TTL: 300, Line: "telecom"}
	p := &replacementProvider{attributedProvider: attributedProvider{batchProvider: batchProvider{rows: []dns.DNSRecord{old, sibling}}, group: "g"}, loseGroup: true}
	changes := []Change{{Action: "replace", ID: old.ID, Name: "new-mail." + origin, Priority: &zero}, {Action: "patch", ID: sibling.ID, Content: "never sent", TTL: 300}}
	stale := previewPlan(t, db, p, changes[:1])
	p.group = "other"
	if err := stale.apply(t.Context(), db, p, zoneScope, origin, changes[:1], allowBatch); err != nil || stale.Items[0].State != "conflict" || p.writes != 0 {
		t.Fatalf("stale source group did not block dispatch: state=%s writes=%d err=%v", stale.Items[0].State, p.writes, err)
	}
	p.group = "g"
	plan := previewPlan(t, db, p, changes)
	if err := plan.apply(t.Context(), db, p, zoneScope, origin, changes, allowBatch); err != nil {
		t.Fatal(err)
	}
	if plan.State != "uncertain" || plan.Items[0].State != "unknown" || plan.Items[1].State != "not_sent" || p.writes != 1 {
		t.Fatalf("lost group reported as success or continued dispatch: %+v", plan.public())
	}
	if got := p.rows[0]; got.ID != "replaced-old" || got.Priority == nil || *got.Priority != 0 || got.Content != "smtp."+origin || got.Status != old.Status || got.Description != old.Description {
		t.Fatal("replacement failed to preserve or update the expected MX data")
	}
	var raw string
	if err := db.Select("items").From("dns_batch_plans").Where(dbx.HashExp{"id": plan.ID}).Row(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "synthetic") || strings.Contains(raw, origin) || strings.Contains(raw, "telecom") {
		t.Fatal("provider data persisted as plaintext")
	}
	loaded, err := loadPlan(db, zoneScope, plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	p.afterList = func() { t.Fatal("revoked reconciliation queried the provider") }
	revoked := errors.New("revoked")
	if err := loaded.reconcile(t.Context(), db, p, zoneScope, origin, func() error { return revoked }); !errors.Is(err, revoked) {
		t.Fatalf("did not report revoked access: %v", err)
	}
	p.afterList = nil
	p.group = "g"
	p.rows[1].TTL++
	if err := loaded.reconcile(t.Context(), db, p, zoneScope, origin, allowBatch); err != nil || loaded.State != "uncertain" || p.writes != 1 {
		t.Fatal("reconciliation accepted changed siblings or dispatched a write")
	}
	p.rows[1] = sibling
	if err := loaded.reconcile(t.Context(), db, p, zoneScope, origin, allowBatch); err != nil || loaded.State != "partial" || loaded.Items[0].State != "observed" || loaded.Items[0].ID != "replaced-old" || p.writes != 1 {
		t.Fatalf("reconciliation could not identify preserved replacement without replay: %+v, %v", loaded.public(), err)
	}
}

func TestReplacementPreviewRejectsIncompatibleTargets(t *testing.T) {
	rows := []dns.DNSRecord{
		{ID: "source", Name: "old." + origin, Type: "A", TTL: 300, Content: "192.0.2.1"},
		{ID: "destination", Name: "new." + origin, Type: "A", TTL: 300, Content: "192.0.2.2"},
		{ID: "alias", Name: "alias." + origin, Type: "CNAME", TTL: 300, Content: "another.test"},
	}
	p := &replacementProvider{}
	zero := 0
	for _, change := range []Change{
		{Action: "replace", ID: "source", Name: "outside.test"},
		{Action: "replace", ID: "source", Name: "new." + origin, Type: "CNAME", Content: "target.test"},
		{Action: "replace", ID: "source", Name: "alias." + origin, Type: "CNAME", Content: "target.test"},
		{Action: "replace", ID: "source", Name: origin, Type: "NS", Content: "target.test"},
		{Action: "replace", ID: "source", Priority: &zero},
		{Action: "replace", ID: "source", Type: "MX", Content: "40 smtp.example.test", Priority: &zero},
	} {
		if _, _, err := prepare(t.Context(), p, zoneScope.provider, zoneScope.zone, origin, rows, []Change{change}); err == nil {
			t.Fatalf("accepted invalid replacement: %+v", change)
		}
	}
	if _, _, err := prepare(t.Context(), &p.batchProvider, zoneScope.provider, zoneScope.zone, origin, rows, []Change{{Action: "replace", ID: "source", Name: "third." + origin}}); err == nil {
		t.Fatal("provider without native replacement was accepted")
	}
}
