package dnsautomation

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	"github.com/pocketbase/pocketbase/core"
	_ "github.com/pocketbase/pocketbase/migrations"
)

const fixtureIP = "93.184.215.14" // Synthetic record; probes are injected and never connect.

type mockProvider struct {
	dns.Provider
	mu        sync.Mutex
	r         *dns.DNSRecord
	writes    int
	writeErr  bool
	dropWrite bool
}

func (p *mockProvider) DNSRecords(ctx context.Context, zone string, page int, name string) (*dns.DNSPage[dns.DNSRecord], error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := &dns.DNSPage[dns.DNSRecord]{}
	if zone == "zone" && p.r != nil {
		out.Items = []dns.DNSRecord{*p.r}
		out.Info.Total = 1
	}
	return out, nil
}
func (p *mockProvider) PatchDNSRecord(_ context.Context, _, _ string, patch dns.RecordPatch) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.writes++
	if !p.dropWrite {
		p.r.Content = patch.Content
		p.r.TTL = patch.TTL
	}
	if p.writeErr {
		return "", errors.New("synthetic timeout")
	}
	return p.r.ID, nil
}
func (p *mockProvider) DeleteDNSRecord(_ context.Context, _, id string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.r = nil
	p.writes++
	return id, nil
}
func (p *mockProvider) SetDNSRecordStatus(_ context.Context, _, id string, on bool) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.r.Status = "DISABLE"
	if on {
		p.r.Status = "ENABLE"
	}
	p.writes++
	return id, nil
}

type fixture struct {
	s       *Service
	p       *mockProvider
	d       Definition
	now     time.Time
	healthy bool
	revoked bool
	events  []Event
}

func setup(t *testing.T) *fixture {
	t.Helper()
	t.Setenv("CERTIMATE_DNS_PROBE_IPS", fixtureIP)
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.ResetBootstrapState() })
	if err := Install(app); err != nil {
		t.Fatal(err)
	}
	f := &fixture{now: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
	f.p = &mockProvider{r: &dns.DNSRecord{ID: "r", Name: "a.example.test", Type: "A", TTL: 300, Content: fixtureIP, Status: "ENABLE"}}
	f.s = New(app, func(_ context.Context, target Target) (dns.Provider, error) {
		if target.AccountID != "access" || f.revoked {
			return nil, errProvider
		}
		return f.p, nil
	}, func(_ context.Context, e Event) error { f.events = append(f.events, e); return nil })
	f.s.check = func(context.Context, Definition) (bool, error) { return f.healthy, nil }
	f.s.now = func() time.Time { return f.now }
	f.d = Definition{Name: "Failover", NotifyAccessID: "notify", Kind: "failover", Target: Target{AccountID: "access", ZoneID: "zone", RecordID: "r", Name: "a.example.test", Type: "A"}, Action: "replace",
		Primary: fixtureIP, Backup: "8.8.8.8", Monitor: Monitor{Protocol: "https", Port: 443, Interval: 10, Timeout: 1, FailureThreshold: 2, RecoveryThreshold: 2, Cooldown: 40}}
	return f
}
func (f *fixture) task(t *testing.T, id string) *Task {
	t.Helper()
	task, err := getTask(t.Context(), f.s.app, id)
	if err != nil {
		t.Fatal(err)
	}
	return task
}
func (f *fixture) control(t *testing.T, id, action string) {
	t.Helper()
	if err := f.s.control(t.Context(), id, "admin", action, f.task(t, id).Version); err != nil {
		t.Fatal(action, err)
	}
}
func (f *fixture) create(t *testing.T) string {
	t.Helper()
	task, err := f.s.Create(t.Context(), "admin", f.d)
	if err != nil {
		t.Fatal(err)
	}
	return task.ID
}
func (f *fixture) tick(t *testing.T, seconds int) {
	t.Helper()
	f.now = f.now.Add(time.Duration(seconds) * time.Second)
	if err := f.s.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
}
func TestFailoverThresholdsRollbackAndCooldown(t *testing.T) {
	f := setup(t)
	id := f.create(t)
	f.tick(t, 0)
	if f.p.writes != 0 {
		t.Fatal("draft ran")
	}
	f.control(t, id, "activate")
	f.tick(t, 0)
	if f.task(t, id).Failures != 1 {
		t.Fatal("first failure not counted")
	}
	f.healthy = true
	f.tick(t, 10)
	f.healthy = false
	f.tick(t, 10)
	f.tick(t, 10)
	if f.p.writes != 1 || f.p.r.Content != f.d.Backup || f.task(t, id).Position != "backup" {
		t.Fatal("transition", f.task(t, id), f.p.r)
	}
	f.healthy = true
	f.tick(t, 10)
	f.tick(t, 10)
	if f.p.writes != 1 {
		t.Fatal("cooldown bypassed")
	}
	f.tick(t, 20)
	if f.p.writes != 2 || f.p.r.Content != f.d.Primary {
		t.Fatal("no recovery")
	}
	f.control(t, id, "pause")
	f.control(t, id, "rollback")
	if f.task(t, id).State != "paused" || f.p.r.Content != f.d.Backup {
		t.Fatal("rollback incomplete")
	}
	f.tick(t, 100)
	items, total, err := f.s.History(t.Context(), id, 1)
	if err != nil || total < 10 || items[0].Action != "rollback" || items[0].Outcome != "verified" || items[0].Before == "" || items[0].After == "" {
		t.Fatal(total, items, err)
	}
	if len(f.events) != 3 {
		t.Fatal("unexpected notification count", f.events)
	}
}
func TestReadbackAndNoReplay(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "timeout_committed", true: "unknown"}[lost], func(t *testing.T) {
			f := setup(t)
			f.d.Kind = "schedule"
			f.d.Action = "update"
			f.d.Value = "8.8.8.8"
			f.d.Schedule = Schedule{Cycle: "once", At: f.now.Add(time.Minute).Format(time.RFC3339)}
			id := f.create(t)
			f.control(t, id, "activate")
			f.p.writeErr = true
			f.p.dropWrite = lost
			f.tick(t, 60)
			f.tick(t, 600)
			task := f.task(t, id)
			if f.p.writes != 1 {
				t.Fatal("unexpected replay")
			}
			if lost {
				if task.State != "review" {
					t.Fatal(task.State)
				}
				f.control(t, id, "reconcile")
				if f.task(t, id).State != "paused" {
					t.Fatal("unreconciled")
				}
			} else if task.State != "completed" {
				t.Fatal(task.State)
			}
		})
	}
}
func TestExpiredLeaseAndRevocation(t *testing.T) {
	f := setup(t)
	id := f.create(t)
	f.control(t, id, "activate")
	task, _, err := f.s.claim(t.Context(), id, "scheduler", "scheduled", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.s.claim(t.Context(), id, "scheduler", "scheduled", 0); !errors.Is(err, errConflict) {
		t.Fatal("duplicate lease", err)
	}
	if err = f.s.control(t.Context(), id, "admin", "pause", task.Version); !errors.Is(err, errConflict) {
		t.Fatal(err)
	}
	f.tick(t, 180)
	if f.task(t, id).State != "review" || f.p.writes != 0 {
		t.Fatal("lost lease was replayed")
	}
	f.control(t, id, "reconcile")
	f.control(t, id, "activate")
	f.revoked = true
	f.tick(t, 10)
	if f.task(t, id).State != "paused" || f.p.writes != 0 {
		t.Fatal("revoked target executed")
	}
}
func TestActivationAndSchedule(t *testing.T) {
	f := setup(t)
	id := f.create(t)
	t.Setenv("CERTIMATE_DNS_PROBE_IPS", "")
	if err := f.s.control(t.Context(), id, "admin", "activate", 1); !errors.Is(err, errProbeDenied) {
		t.Fatal(err)
	}
	for _, ip := range []string{"localhost", "0.0.0.0", "127.0.0.1", "10.2.1.1", "100.64.0.1", "168.63.129.16", "169.254.169.254", "::ffff:127.0.0.1", "2002:c000:201::1", "fd00::1", "64:ff9b::a00:1", "2001::1"} {
		if allowedProbeIP(ip) {
			t.Fatal("accepted", ip)
		}
	}
	for _, c := range []struct {
		s    Schedule
		at   string
		want string
	}{
		{Schedule{Cycle: "daily", Timezone: "America/New_York", At: "02:30"}, "2026-03-08T05:00:00Z", "2026-03-09T06:30:00Z"},
		{Schedule{Cycle: "monthly", Timezone: "UTC", At: "00:05", Day: 31}, "2026-02-01T00:00:00Z", "2026-03-31T00:05:00Z"},
		{Schedule{Cycle: "weekly", Timezone: "Asia/Shanghai", At: "08:15", Day: 0}, "2026-03-08T01:00:00Z", "2026-03-15T00:15:00Z"},
	} {
		now, _ := time.Parse(time.RFC3339, c.at)
		next, err := c.s.next(now)
		if err != nil || next.UTC().Format(time.RFC3339) != c.want {
			t.Fatal(next, err)
		}
	}
}
