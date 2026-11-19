package dnsautomation

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

// Use private SQLite tables so the generic PocketBase records API cannot
// bypass validation, activation, history immutability, or the execution lease.
func Install(app core.App) error {
	for _, stmt := range []string{
		`CREATE TABLE dns_automation_tasks (
			id TEXT PRIMARY KEY, config TEXT NOT NULL CHECK(json_valid(config)),
			state TEXT NOT NULL DEFAULT 'draft', position TEXT NOT NULL DEFAULT 'primary',
			failures INTEGER NOT NULL DEFAULT 0, recoveries INTEGER NOT NULL DEFAULT 0,
			next_at INTEGER NOT NULL DEFAULT 0, last_at INTEGER NOT NULL DEFAULT 0, switch_at INTEGER NOT NULL DEFAULT 0,
			lease TEXT NOT NULL DEFAULT '', lease_end INTEGER NOT NULL DEFAULT 0,
			version INTEGER NOT NULL DEFAULT 1)`,
		`CREATE INDEX idx_dns_automation_due ON dns_automation_tasks(state,next_at,lease_end)`,
		`CREATE UNIQUE INDEX idx_dns_automation_record_lease ON dns_automation_tasks(
			json_extract(config,'$.target.accountId'),json_extract(config,'$.target.zoneId'),json_extract(config,'$.target.recordId')) WHERE lease<>''`,
		`CREATE UNIQUE INDEX idx_dns_automation_active_monitor ON dns_automation_tasks(
			json_extract(config,'$.target.accountId'),json_extract(config,'$.target.zoneId'),json_extract(config,'$.target.recordId'))
			WHERE state='active' AND json_extract(config,'$.kind')='failover'`,
		`CREATE TABLE dns_automation_runs(
			id TEXT PRIMARY KEY,task_id TEXT NOT NULL REFERENCES dns_automation_tasks(id),
			actor TEXT NOT NULL, action TEXT NOT NULL, outcome TEXT NOT NULL,
			started INTEGER NOT NULL, finished INTEGER NOT NULL DEFAULT 0, before_record TEXT NOT NULL DEFAULT '',
			after_record TEXT NOT NULL DEFAULT '', notification TEXT NOT NULL DEFAULT '')`,
		`CREATE INDEX idx_dns_automation_history ON dns_automation_runs(task_id,started DESC)`,
	} {
		if _, err := app.DB().NewQuery(stmt).Execute(); err != nil {
			return err
		}
	}
	return nil
}

type Service struct {
	heartbeat atomic.Int64
	app       core.App
	resolve   Resolver
	notify    Notifier
	check     func(context.Context, Definition) (bool, error)
	now       func() time.Time
}

func New(app core.App, resolve Resolver, notify Notifier) *Service {
	return &Service{app: app, resolve: resolve, notify: notify, check: probe, now: time.Now}
}

func (s *Service) LastTick() int64 { return s.heartbeat.Load() }

func newID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

var idRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func (d Definition) Validate() error { return d.validate(time.Now()) }

func getTask(ctx context.Context, app core.App, id string) (*Task, error) {
	var t Task
	err := app.DB().NewQuery("SELECT * FROM dns_automation_tasks WHERE id={:id}").Bind(dbx.Params{"id": id}).WithContext(ctx).One(&t)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal([]byte(t.Config), &t.Definition); err != nil {
		return nil, err
	}
	return &t, nil
}

func audit(ctx context.Context, app core.App, id, task, actor, action, outcome string, at int64) error {
	end := at
	if outcome == "running" {
		end = 0
	}
	_, err := app.DB().NewQuery(`INSERT INTO dns_automation_runs(id,task_id,actor,action,outcome,started,finished)
		VALUES({:id},{:task},{:actor},{:action},{:outcome},{:at},{:end})`).Bind(dbx.Params{
		"id": id, "task": task, "actor": actor, "action": action, "outcome": outcome, "at": at, "end": end}).WithContext(ctx).Execute()
	return err
}

func affected(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errConflict
	}
	return nil
}

func (s *Service) Create(ctx context.Context, actor string, d Definition) (*Task, error) {
	return s.CreateDraftWithID(ctx, newID(), actor, d)
}

func (s *Service) CreateDraftWithID(ctx context.Context, id, actor string, d Definition) (*Task, error) {
	if !idRE.MatchString(id) || actor == "" || len(actor) > 128 {
		return nil, errInput
	}
	if err := d.validate(s.now()); err != nil {
		return nil, err
	}
	cfg, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	err = s.app.RunInTransaction(func(tx core.App) error {
		if err := affected(tx.DB().NewQuery("INSERT INTO dns_automation_tasks(id,config) VALUES({:id},{:cfg}) ON CONFLICT(id) DO NOTHING").Bind(dbx.Params{"id": id, "cfg": string(cfg)}).WithContext(ctx).Execute()); err != nil {
			return err
		}
		return audit(ctx, tx, newID(), id, actor, "create", "ok", s.now().Unix())
	})
	if err != nil {
		return nil, err
	}
	return getTask(ctx, s.app, id)
}

var errProbeDenied = errors.New("probe origin must be listed in CERTIMATE_DNS_PROBE_IPS")

func (s *Service) Edit(ctx context.Context, id, actor string, version int, d Definition) error {
	if err := d.validate(s.now()); err != nil {
		return err
	}
	cfg, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return s.app.RunInTransaction(func(tx core.App) error {
		if err := affected(tx.DB().NewQuery(`UPDATE dns_automation_tasks SET config={:cfg},state='draft',position='primary',
			failures=0,recoveries=0,switch_at=0,last_at=0,next_at=0,version=version+1
			WHERE id={:id} AND version={:v} AND lease='' AND state IN ('draft','paused','completed')`).
			Bind(dbx.Params{"id": id, "v": version, "cfg": string(cfg)}).WithContext(ctx).Execute()); err != nil {
			return err
		}
		return audit(ctx, tx, newID(), id, actor, "edit", "ok", s.now().Unix())
	})
}

func (s *Service) change(ctx context.Context, t *Task, actor, action, state string, next int64) error {
	return s.app.RunInTransaction(func(tx core.App) error {
		if err := affected(tx.DB().NewQuery(`UPDATE OR IGNORE dns_automation_tasks SET state={:state},next_at={:next},failures=0,recoveries=0,version=version+1
			WHERE id={:id} AND version={:v} AND lease=''`).Bind(dbx.Params{"state": state, "next": next, "id": t.ID, "v": t.Version}).WithContext(ctx).Execute()); err != nil {
			return err
		}
		return audit(ctx, tx, newID(), t.ID, actor, action, "ok", s.now().Unix())
	})
}

func (s *Service) control(ctx context.Context, id, actor, action string, version int) error {
	t, err := getTask(ctx, s.app, id)
	if err != nil {
		return err
	}
	if t.Version != version || t.Lease != "" || t.State == "archived" {
		return errConflict
	}
	switch action {
	case "pause":
		if t.State != "active" {
			return errConflict
		}
		return s.change(ctx, t, actor, action, "paused", 0)
	case "archive":
		if t.State == "active" {
			return errConflict
		}
		return s.change(ctx, t, actor, action, "archived", 0)
	case "activate":
		if t.State != "draft" && t.State != "paused" {
			return errConflict
		}
		d := t.Definition
		now := s.now()
		if err = d.validate(now); err != nil {
			return err
		}
		if d.Kind == "failover" && d.Action != "standby" && !authorizedProbe(d.probeOrigin()) {
			return errProbeDenied
		}
		p, r, err := s.read(ctx, d.Target)
		if err != nil {
			return err
		}
		if err = preflight(d, t.Position, p, r); err != nil {
			return err
		}
		next := now
		if d.Kind == "schedule" {
			next, err = d.Schedule.next(now)
			if err != nil || !next.After(now) {
				return errInput
			}
		}
		return s.change(ctx, t, actor, action, "active", next.Unix())
	case "run":
		if t.State != "active" {
			return errConflict
		}
		return s.execute(ctx, id, actor, "manual", version)
	case "rollback":
		if t.State != "paused" && t.State != "completed" {
			return errConflict
		}
		return s.execute(ctx, id, actor, "rollback", version)
	case "reconcile":
		if t.State != "review" {
			return errConflict
		}
		return s.execute(ctx, id, actor, "reconcile", version)
	}
	return errInput
}

func (s *Service) List(ctx context.Context, page int) ([]Task, int, error) {
	var total int
	items := []Task{}
	err := s.app.RunInTransaction(func(tx core.App) error {
		if err := tx.DB().NewQuery("SELECT count(*) FROM dns_automation_tasks WHERE state<>'archived'").WithContext(ctx).Row(&total); err != nil {
			return err
		}
		if err := tx.DB().NewQuery("SELECT * FROM dns_automation_tasks WHERE state<>'archived' ORDER BY rowid DESC LIMIT 20 OFFSET {:off}").Bind(dbx.Params{"off": (page - 1) * 20}).WithContext(ctx).All(&items); err != nil {
			return err
		}
		for i := range items {
			if err := json.Unmarshal([]byte(items[i].Config), &items[i].Definition); err != nil {
				return err
			}
		}
		return nil
	})
	return items, total, err
}

func (s *Service) History(ctx context.Context, id string, page int) ([]Run, int, error) {
	var total int
	items := []Run{}
	params := dbx.Params{"id": id, "off": (page - 1) * 20}
	err := s.app.RunInTransaction(func(tx core.App) error {
		if _, err := getTask(ctx, tx, id); err != nil {
			return err
		}
		if err := tx.DB().NewQuery("SELECT count(*) FROM dns_automation_runs WHERE task_id={:id}").Bind(params).WithContext(ctx).Row(&total); err != nil {
			return err
		}
		return tx.DB().NewQuery("SELECT * FROM dns_automation_runs WHERE task_id={:id} ORDER BY started DESC,rowid DESC LIMIT 20 OFFSET {:off}").Bind(params).WithContext(ctx).All(&items)
	})
	return items, total, err
}

func publicError(err error) (int, string) {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 404, "automation task unavailable"
	case errors.Is(err, errInput):
		return 400, errInput.Error()
	case errors.Is(err, errConflict), errors.Is(err, errIdentity), errors.Is(err, errMissing):
		return 409, err.Error()
	case errors.Is(err, errProbeDenied):
		return 422, errProbeDenied.Error()
	case errors.Is(err, errProvider):
		return 502, errProvider.Error()
	default:
		return 500, "automation operation failed"
	}
}
