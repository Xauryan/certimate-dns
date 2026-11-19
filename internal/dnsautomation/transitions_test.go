package dnsautomation

import (
	"context"
	"testing"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type rotatingRecord struct{ *mockProvider }

func (p rotatingRecord) PatchDNSRecord(ctx context.Context, zone, id string, patch dns.RecordPatch) (string, error) {
	if p.r.ID != id {
		return "", errMissing
	}
	_, err := p.mockProvider.PatchDNSRecord(ctx, zone, id, patch)
	if err != nil {
		return "", err
	}
	p.r.ID += "x"
	return p.r.ID, nil
}

func TestReplacementIDsSurviveRollback(t *testing.T) {
	f := setup(t)
	f.s.resolve = func(context.Context, Target) (dns.Provider, error) { return rotatingRecord{f.p}, nil }
	id := f.create(t)
	f.control(t, id, "activate")
	f.tick(t, 0)
	f.tick(t, 10)
	if target := f.task(t, id).Definition.Target; target.RecordID != "rx" || f.p.r.Content != f.d.Backup {
		t.Fatal("replacement not adopted", target)
	}
	f.control(t, id, "pause")
	f.control(t, id, "rollback")
	if target := f.task(t, id).Definition.Target; target.RecordID != "rxx" || f.p.r.Content != f.d.Primary {
		t.Fatal("rollback lost replacement ID", target)
	}
}

func TestMonitorAndStandbyWithoutPeerObservations(t *testing.T) {
	f := setup(t)
	f.d.Action = "observe"
	id := f.create(t)
	f.control(t, id, "activate")
	f.tick(t, 0)
	f.tick(t, 10)
	if f.task(t, id).Position != "backup" || f.p.writes != 0 || len(f.events) != 1 || f.events[0].Outcome != "failed" {
		t.Fatal("monitor transition", f.events)
	}
	f.control(t, id, "pause")
	f.d.Action = "standby"
	f.p.r.Status = "DISABLE"
	sid := f.create(t)
	f.control(t, sid, "activate")
	f.tick(t, 0)
	if st := f.task(t, sid); st.State != "active" || st.NextAt <= f.now.Unix() || f.p.writes != 0 {
		t.Fatal("standby did not wait for observations", st)
	}
}

type proxiedRecord struct{ *mockProvider }

func (p proxiedRecord) PatchDNSRecordProxy(ctx context.Context, zone, id string, patch dns.RecordPatch, proxied bool) (string, error) {
	got, err := p.PatchDNSRecord(ctx, zone, id, patch)
	if err == nil {
		p.r.Proxied = proxied
	}
	return got, err
}
func TestProxiedFailoverRestoresTTL(t *testing.T) {
	f := setup(t)
	f.s.resolve = func(context.Context, Target) (dns.Provider, error) { return proxiedRecord{f.p}, nil }
	f.d.BackupProxied = true
	id := f.create(t)
	f.control(t, id, "activate")
	f.tick(t, 0)
	f.tick(t, 10)
	if !f.p.r.Proxied || f.p.r.TTL != 1 || f.p.r.Content != f.d.Backup {
		t.Fatal("failed to proxy backup", f.p.r)
	}
	f.healthy = true
	f.tick(t, 10)
	f.tick(t, 30)
	if f.p.r.Proxied || f.p.r.TTL != 300 || f.p.r.Content != f.d.Primary {
		t.Fatal("failed to restore primary settings", f.p.r)
	}
}
