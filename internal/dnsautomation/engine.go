package dnsautomation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

// Run blocks until cancellation. Each tick handles a bounded page. Expired
// leases enter review instead of resubmitting a possibly committed cloud write.
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if err := s.Tick(ctx); err != nil && ctx.Err() == nil {
			s.app.Logger().Error("DNS automation tick failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Service) Tick(ctx context.Context) error {
	now := s.now().Unix()
	err := s.app.RunInTransaction(func(tx core.App) error {
		if _, err := tx.DB().NewQuery(`UPDATE dns_automation_runs SET outcome='interrupted',finished={:now} WHERE id IN
			(SELECT lease FROM dns_automation_tasks WHERE lease<>'' AND lease_end<={:now}) AND outcome='running'`).
			Bind(dbx.Params{"now": now}).WithContext(ctx).Execute(); err != nil {
			return err
		}
		_, err := tx.DB().NewQuery(`UPDATE dns_automation_tasks SET lease='',lease_end=0,state='review',next_at=0,version=version+1
			WHERE lease<>'' AND lease_end<={:now}`).Bind(dbx.Params{"now": now}).WithContext(ctx).Execute()
		return err
	})
	if err != nil {
		return err
	}
	s.heartbeat.Store(now)
	var ids []string
	err = s.app.DB().NewQuery(`SELECT id FROM dns_automation_tasks WHERE state='active' AND lease='' AND next_at>0 AND next_at<={:now}
		ORDER BY next_at,id LIMIT 25`).Bind(dbx.Params{"now": now}).WithContext(ctx).Column(&ids)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := s.execute(ctx, id, "scheduler", "scheduled", 0); err != nil && !errors.Is(err, errConflict) {
			s.app.Logger().Error("DNS automation run failed", "task", id)
		}
	}
	return nil
}

func (s *Service) claim(ctx context.Context, id, actor, mode string, version int) (*Task, string, error) {
	var t *Task
	run := newID()
	now := s.now().Unix()
	err := s.app.RunInTransaction(func(tx core.App) error {
		var err error
		t, err = getTask(ctx, tx, id)
		if err != nil {
			return err
		}
		if t.Lease != "" || (mode != "scheduled" && t.Version != version) {
			return errConflict
		}
		switch mode {
		case "rollback":
			if t.State != "paused" && t.State != "completed" {
				return errConflict
			}
		case "reconcile":
			if t.State != "review" {
				return errConflict
			}
		default:
			if t.State != "active" || (mode == "scheduled" && (t.NextAt <= 0 || t.NextAt > now)) {
				return errConflict
			}
		}
		if err := affected(tx.DB().NewQuery(`UPDATE OR IGNORE dns_automation_tasks SET lease={:run},lease_end={:end},version=version+1
			WHERE id={:id} AND version={:v} AND lease=''`).Bind(dbx.Params{"run": run, "end": now + 180, "id": id, "v": t.Version}).WithContext(ctx).Execute()); err != nil {
			return err
		}
		return audit(ctx, tx, run, id, actor, mode, "running", now)
	})
	return t, run, err
}

func (s *Service) finish(ctx context.Context, t *Task, run, action, outcome string) error {
	now := s.now().Unix()
	return s.app.RunInTransaction(func(tx core.App) error {
		if err := affected(tx.DB().NewQuery(`UPDATE dns_automation_tasks SET lease='',lease_end=0,state={:state},position={:pos},
			failures={:f},recoveries={:r},switch_at={:switch},last_at={:now},next_at={:next},version=version+1
			WHERE id={:id} AND lease={:run} AND lease_end>{:now}`).Bind(dbx.Params{"id": t.ID, "run": run, "state": t.State, "pos": t.Position, "f": t.Failures, "r": t.Recoveries,
			"switch": t.SwitchAt, "now": now, "next": t.NextAt}).WithContext(ctx).Execute()); err != nil {
			return err
		}
		return affected(tx.DB().NewQuery(`UPDATE dns_automation_runs SET action={:action},outcome={:outcome},finished={:now} WHERE id={:run} AND outcome='running'`).
			Bind(dbx.Params{"action": action, "outcome": outcome, "now": now, "run": run}).WithContext(ctx).Execute())
	})
}

func (s *Service) execute(ctx context.Context, id, actor, mode string, version int) error {
	ctx, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()
	t, run, err := s.claim(ctx, id, actor, mode, version)
	if err != nil {
		return err
	}
	action, outcome := "inspect", "ok"
	switch mode {
	case "rollback":
		action, outcome, err = s.rollback(ctx, t, run)
	case "reconcile":
		action, outcome, err = s.reconcile(ctx, t)
	default:
		action, outcome, err = s.evaluate(ctx, t, run)
	}
	if err != nil {
		if mode == "reconcile" || outcome == "uncertain" || outcome == "drift" {
			t.State = "review"
		} else {
			t.State = "paused"
		}
		t.NextAt = 0
	}
	// Shutdown or a client disconnect after a provider request must still
	// commit the observed outcome; a process crash falls back to lease review.
	final, done := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer done()
	if e := s.finish(final, t, run, action, outcome); e != nil {
		return e
	}
	if s.notify != nil && action != "probe" {
		event := Event{TaskID: id, RunID: run, AccessID: t.Definition.NotifyAccessID, Action: action, Outcome: outcome}
		status := "sent"
		if e := s.notify(final, event); e != nil {
			status = "failed"
			if errors.Is(e, ErrNoNotification) {
				status = "skipped"
			}
		}
		_, e := s.app.DB().NewQuery("UPDATE dns_automation_runs SET notification={:status} WHERE id={:run}").Bind(dbx.Params{"status": status, "run": run}).WithContext(context.WithoutCancel(ctx)).Execute()
		if e != nil {
			return e
		}
	}
	return err
}

func (s *Service) evaluate(ctx context.Context, t *Task, run string) (string, string, error) {
	d := t.Definition
	if err := d.validate(s.now()); err != nil {
		return "inspect", "invalid", err
	}
	p, current, err := s.read(ctx, d.Target)
	if err != nil {
		return "inspect", "unavailable", err
	}
	if err = preflight(d, t.Position, p, current); err != nil {
		return "inspect", "drift", err
	}
	act := d.Action
	target := *current
	want := &target
	if d.Kind == "failover" {
		healthy, err := s.health(ctx, t)
		m := d.Monitor
		t.NextAt = s.now().Unix() + int64(m.Interval)
		if errors.Is(err, errAwaitPeers) {
			t.Failures = 0
			t.Recoveries = 0
			return "probe", "awaiting_peers", nil
		}
		if err != nil || ctx.Err() != nil {
			return "inspect", "probe_unavailable", errProvider
		}
		if healthy {
			t.Failures = 0
			t.Recoveries = min(t.Recoveries+1, m.RecoveryThreshold)
		} else {
			t.Recoveries = 0
			t.Failures = min(t.Failures+1, m.FailureThreshold)
		}
		shouldFail := t.Position == "primary" && t.Failures >= m.FailureThreshold
		shouldRecover := t.Position == "backup" && t.Recoveries >= m.RecoveryThreshold
		if (!shouldFail && !shouldRecover) || (t.SwitchAt > 0 && s.now().Unix()-t.SwitchAt < int64(m.Cooldown)) {
			if healthy {
				return "probe", "healthy", nil
			}
			return "probe", "unhealthy", nil
		}
		switch d.Action {
		case "observe":
			act = "monitor"
		case "replace":
			target.Content = d.Primary
			if shouldFail {
				target.Content = d.Backup
			}
			if d.BackupProxied {
				target.Proxied = shouldFail
				if shouldFail {
					target.TTL = 1
				} else {
					prior, e := s.lastMutation(ctx, t.ID)
					if e != nil {
						return "inspect", "drift", errConflict
					}
					original, e := decodeSnapshot(prior.Before)
					if e != nil || original == nil || original.Proxied || !sameValue(original.Type, original.Content, d.Primary) {
						return "inspect", "drift", errConflict
					}
					target.TTL = original.TTL
				}
			}
		case "disable", "standby":
			on := (d.Action == "standby") == shouldFail
			act = "disable"
			if on {
				act = "enable"
			}
		}
	} else {
		switch d.Action {
		case "update":
			target.Content = d.Value
			if d.Schedule.Proxied != nil {
				target.Proxied = *d.Schedule.Proxied
				if target.Proxied {
					target.TTL = 1
				}
			}
		case "delete":
			want = nil
		}
	}
	if act == "enable" {
		target.Status = "enabled"
	} else if act == "disable" {
		target.Status = "disabled"
	}
	outcome, err := s.apply(ctx, t, run, act, current, want)
	if err != nil {
		return act, outcome, err
	}
	if d.Kind == "failover" {
		if act == "monitor" {
			outcome = "recovered"
			if t.Position == "primary" {
				outcome = "failed"
			}
		}
		if t.Position == "primary" {
			t.Position = "backup"
		} else {
			t.Position = "primary"
		}
		t.Failures = 0
		t.Recoveries = 0
		t.SwitchAt = s.now().Unix()
	} else if d.Schedule.Cycle == "once" {
		t.State = "completed"
		t.NextAt = 0
	} else {
		next, err := d.Schedule.next(s.now())
		if err != nil {
			return act, "schedule_invalid", err
		}
		t.NextAt = next.Unix()
	}
	return act, outcome, nil
}

var errAwaitPeers = errors.New("waiting for peer observations")

func (s *Service) health(ctx context.Context, t *Task) (bool, error) {
	d := t.Definition
	if d.Action != "standby" {
		return s.check(ctx, d)
	}
	// Standby follows only active, recently observed disable-on-failure peers
	// in this account and Zone with exactly the same DNS owner name.
	var peers, fresh, healthy int
	err := s.app.DB().NewQuery(`SELECT count(*),count(CASE WHEN last_at>0 AND last_at>=({:now}-2*json_extract(config,'$.monitor.interval')) THEN 1 END),coalesce(sum(CASE WHEN position='primary' THEN 1 ELSE 0 END),0)
		FROM dns_automation_tasks WHERE state='active' AND json_extract(config,'$.kind')='failover' AND json_extract(config,'$.action')='disable'
		AND json_extract(config,'$.target.accountId')={:account} AND json_extract(config,'$.target.zoneId')={:zone}
		AND json_extract(config,'$.target.type')={:type}
        AND lower(rtrim(json_extract(config,'$.target.name'),'.'))=lower(rtrim({:name},'.'))`).Bind(dbx.Params{"account": d.Target.AccountID, "zone": d.Target.ZoneID, "name": d.Target.Name, "type": d.Target.Type, "now": s.now().Unix()}).WithContext(ctx).Row(&peers, &fresh, &healthy)
	if err != nil {
		return false, err
	}
	if peers == 0 || peers != fresh {
		return false, errAwaitPeers
	}
	return healthy > d.Monitor.HealthyLimit, nil
}

// Persist the intent before issuing the cloud mutation. Timeouts and rejected
// writes always get a fresh read, including when the SDK reports success.
func (s *Service) apply(ctx context.Context, t *Task, run, act string, before, want *dns.DNSRecord) (string, error) {
	if want != nil && before != nil {
		want.ID = before.ID
	}
	if sameRecord(before, want) {
		return "unchanged", nil
	}
	p, live, err := s.read(ctx, t.Definition.Target)
	if err != nil || !sameRecord(before, live) {
		return "drift", errIdentity
	}
	if err := affected(s.app.DB().NewQuery(`UPDATE dns_automation_runs SET action={:action},before_record={:before},after_record={:after}
		WHERE id={:run} AND outcome='running' AND EXISTS (SELECT 1 FROM dns_automation_tasks WHERE id={:id} AND lease={:run} AND lease_end>{:now})`).
		Bind(dbx.Params{"action": act, "before": snapshot(before), "after": snapshot(want), "run": run, "id": t.ID, "now": s.now().Unix()}).WithContext(ctx).Execute()); err != nil {
		return "unavailable", err
	}
	id, writeErr := write(ctx, p, t.Definition.Target, act, before, want)
	if want != nil {
		// Some adapters key records by content. The returned ID is the single
		// authoritative handle for readback, later runs and rollback.
		want.ID = t.Definition.Target.RecordID
		if writeErr == nil && id != "" && id != want.ID {
			want.ID = id
			t.Definition.Target.RecordID = id
			cfg, err := json.Marshal(t.Definition)
			if err != nil {
				return "uncertain", err
			}
			finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			err = s.app.RunInTransaction(func(tx core.App) error {
				params := dbx.Params{"cfg": string(cfg), "id": t.ID, "run": run, "after": snapshot(want)}
				if err := affected(tx.DB().NewQuery("UPDATE dns_automation_tasks SET config={:cfg} WHERE id={:id} AND lease={:run}").Bind(params).WithContext(finishCtx).Execute()); err != nil {
					return err
				}
				return affected(tx.DB().NewQuery("UPDATE dns_automation_runs SET after_record={:after} WHERE id={:run} AND outcome='running'").Bind(params).WithContext(finishCtx).Execute())
			})
			if err != nil {
				return "uncertain", err
			}
		}
	}
	seen, readErr := readComparable(ctx, p, t.Definition.Target)
	if readErr == nil && sameRecord(want, seen) {
		return "verified", nil
	}
	// A transport timeout can arrive before the provider commits. Even an
	// immediate read of the old value cannot safely prove the write failed.
	return "uncertain", errProvider
}

func (s *Service) lastMutation(ctx context.Context, id string) (*Run, error) {
	var r Run
	err := s.app.DB().NewQuery(`SELECT * FROM dns_automation_runs WHERE task_id={:id} AND before_record<>'' AND rowid>coalesce((SELECT max(rowid) FROM dns_automation_runs WHERE task_id={:id} AND action='edit'),0) ORDER BY started DESC,rowid DESC LIMIT 1`).
		Bind(dbx.Params{"id": id}).WithContext(ctx).One(&r)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errConflict
	}
	return &r, err
}

func (s *Service) rollback(ctx context.Context, t *Task, run string) (string, string, error) {
	prior, err := s.lastMutation(ctx, t.ID)
	if err != nil || prior.Outcome != "verified" {
		return "rollback", "unavailable", errConflict
	}
	before, err := decodeSnapshot(prior.Before)
	if err != nil || before == nil {
		return "rollback", "unavailable", errConflict
	}
	after, err := decodeSnapshot(prior.After)
	if err != nil || after == nil {
		return "rollback", "unavailable", errConflict
	} // deletion requires manual restoration using provider metadata
	if prior.Action == "rollback" || prior.Action == "restore" {
		return "rollback", "unavailable", errConflict
	}
	act := "restore"
	if prior.Action == "enable" || prior.Action == "disable" {
		on, ok := enabled(before.Status)
		if !ok {
			return "rollback", "unavailable", errProvider
		}
		act = "disable"
		if on {
			act = "enable"
		}
	}
	outcome, err := s.apply(ctx, t, run, act, after, before)
	if err == nil {
		t.State = "paused"
		t.NextAt = 0
		t.Position = "primary"
		t.Failures = 0
		t.Recoveries = 0
		t.SwitchAt = s.now().Unix()
		if t.Definition.Kind == "failover" && t.Definition.Action == "replace" && sameValue(before.Type, before.Content, t.Definition.Backup) {
			t.Position = "backup"
		}
		if t.Definition.Kind == "failover" && t.Definition.Action != "replace" {
			on, _ := enabled(before.Status)
			if on == (t.Definition.Action == "standby") {
				t.Position = "backup"
			}
		}
	}
	// Record rollback as its own action so a repeated request cannot undo the rollback.
	return "rollback", outcome, err
}

func (s *Service) reconcile(ctx context.Context, t *Task) (string, string, error) {
	// An interrupted probe with no write intent can be released directly.
	var r Run
	err := s.app.DB().NewQuery(`SELECT * FROM dns_automation_runs WHERE task_id={:id} AND outcome IN ('interrupted','uncertain','drift')
		AND action<>'reconcile' ORDER BY started DESC,rowid DESC LIMIT 1`).Bind(dbx.Params{"id": t.ID}).WithContext(ctx).One(&r)
	if err != nil {
		return "reconcile", "unavailable", errConflict
	}
	if r.Before == "" {
		t.State = "paused"
		return "reconcile", "no_write", nil
	}
	p, live, err := s.read(ctx, t.Definition.Target)
	if errors.Is(err, errMissing) && p != nil {
		err = nil
		live = nil
	}
	if err != nil {
		return "reconcile", "unavailable", err
	}
	before, e := decodeSnapshot(r.Before)
	after, f := decodeSnapshot(r.After)
	if e != nil || f != nil {
		return "reconcile", "unavailable", errConflict
	}
	t.State = "paused"
	if sameRecord(live, after) {
		if t.Definition.Kind == "failover" {
			if t.Position == "primary" {
				t.Position = "backup"
			} else {
				t.Position = "primary"
			}
			t.SwitchAt = s.now().Unix()
		}
		return "reconcile", "applied", nil
	}
	if sameRecord(live, before) {
		return "reconcile", "original", nil
	}
	return "reconcile", "drift", errIdentity
}
