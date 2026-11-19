package dnsoptimize

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type Resolver func(ctx context.Context, provider, access, zone string) (dns.Provider, error)
type cachedFeed struct {
	at   time.Time
	data candidates
}
type Service struct {
	app        core.App
	resolve    Resolver
	feedClient *feedClient
	fetch      func(context.Context, Feed) (candidates, error)
	gate       chan struct{}
	feedMu     sync.Mutex
	cache      map[Feed]cachedFeed
	lifecycle  sync.Mutex
	cancel     context.CancelFunc
	done       chan struct{}
}

func New(app core.App, resolve Resolver) *Service {
	feeds := defaultFeedClient()
	return &Service{app: app, resolve: resolve, feedClient: feeds, fetch: feeds.load, gate: make(chan struct{}, 1), cache: map[Feed]cachedFeed{}}
}

func (s *Service) addresses(ctx context.Context, f Feed) (candidates, error) {
	if !f.valid() {
		return nil, domain.ErrInvalidParams
	}
	s.feedMu.Lock()
	defer s.feedMu.Unlock()
	if current, ok := s.cache[f]; ok && time.Since(current.at) < time.Minute {
		return current.data, nil
	}
	data, err := s.fetch(ctx, f)
	if err == nil {
		s.cache[f] = cachedFeed{time.Now(), data}
	}
	return data, err
}
func (s *Service) preview(ctx context.Context, t Target, spec Spec) (dns.Provider, Plan, error) {
	zoneName, err := catalogName(ctx, s.app, t)
	if err != nil {
		return nil, Plan{}, err
	}
	normalized, err := normalize(t, zoneName, spec)
	if err != nil {
		return nil, Plan{}, err
	}
	p, err := s.resolve(ctx, t.Provider, t.Access, t.Zone)
	if err != nil {
		return nil, Plan{}, err
	}
	feed, err := s.addresses(ctx, normalized.feed())
	if err != nil {
		return nil, Plan{}, err
	}
	records, err := matchingRecords(ctx, p, t, normalized)
	if err != nil {
		return nil, Plan{}, err
	}
	plan, err := buildPlan(t, normalized, feed, records)
	return p, plan, err
}
func (s *Service) lock(ctx context.Context) error {
	select {
	case s.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Service) unlock() { <-s.gate }

// Persist the reviewed values before the first provider write. An interrupted run keeps its pending snapshot.
func (s *Service) apply(ctx context.Context, t Target, spec Spec, digest, task, actor string) (Plan, error) {
	p, plan, err := s.preview(ctx, t, spec)
	if err != nil {
		return Plan{}, err
	}
	if (digest != "" || task == "") && plan.Digest != digest {
		return Plan{}, domain.NewError(409, "DNS records, settings or selected addresses have changed; preview again")
	}
	data, err := json.Marshal(plan)
	if err != nil {
		return Plan{}, err
	}
	args := t.params()
	args["actor"] = actor
	args["task"] = task
	args["started"] = time.Now().Unix()
	args["plan"] = string(data)
	var runID int64
	err = s.app.RunInTransaction(func(tx core.App) error {
		res, err := tx.DB().NewQuery(`INSERT INTO dns_optimize_runs(provider,access,zone,task,actor,started,plan,status) VALUES({:provider},{:access},{:zone},{:task},{:actor},{:started},{:plan},'pending')`).WithContext(ctx).Bind(args).Execute()
		if err != nil {
			return err
		}
		runID, err = res.LastInsertId()
		if err != nil {
			return err
		}
		_, err = tx.DB().NewQuery("DELETE FROM dns_optimize_runs WHERE " + scoped + " AND id NOT IN (SELECT id FROM dns_optimize_runs WHERE " + scoped + " ORDER BY id DESC LIMIT 100)").WithContext(ctx).Bind(t.params()).Execute()
		return err
	})
	if err != nil {
		return Plan{}, errors.New("could not save the DNS change snapshot")
	}
	spec.Name = plan.Name
	err = applyPlan(ctx, p, t, spec, plan)
	status := "success"
	if err != nil {
		status = err.Error()
	}
	_, saveErr := s.app.DB().NewQuery("UPDATE dns_optimize_runs SET status={:status} WHERE id={:id}").Bind(dbx.Params{"status": status, "id": runID}).Execute()
	if saveErr != nil {
		return Plan{}, errors.New("could not save the result of DNS verification")
	}
	return plan, err
}

func (s *Service) Start() {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.done = make(chan struct{})
	go func(done chan struct{}) {
		defer close(done)
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			s.runDue(ctx)
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}(s.done)
}
func (s *Service) Stop() {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.cancel != nil {
		s.cancel()
		<-s.done
		s.cancel = nil
	}
}

func (s *Service) runDue(ctx context.Context) {
	now := time.Now().Unix()
	var rows []struct {
		ID string `db:"id"`
	}
	err := s.app.DB().NewQuery("SELECT id FROM dns_optimize_tasks WHERE enabled=1 AND due<={:now} AND lease<={:now} ORDER BY due,id LIMIT 20").WithContext(ctx).Bind(dbx.Params{"now": now}).All(&rows)
	if err != nil {
		if ctx.Err() == nil {
			s.app.Logger().Error("Could not list due DNS optimization tasks")
		}
		return
	}
	for _, row := range rows {
		if s.lock(ctx) != nil {
			return
		}
		s.runTask(ctx, row.ID)
		s.unlock()
	}
}
func (s *Service) runTask(parent context.Context, id string) {
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	now := time.Now()
	deadline := now.Add(3 * time.Minute).Unix()
	params := dbx.Params{"id": id, "now": now.Unix(), "lease": deadline}
	var row taskRow
	claimed := false
	err := s.app.RunInTransaction(func(tx core.App) error {
		res, err := tx.DB().NewQuery("UPDATE dns_optimize_tasks SET lease={:lease} WHERE id={:id} AND enabled=1 AND due<={:now} AND lease<={:now}").WithContext(ctx).Bind(params).Execute()
		if err != nil {
			return err
		}
		count, err := res.RowsAffected()
		if err != nil || count != 1 {
			return err
		}
		claimed = true
		return tx.DB().NewQuery("SELECT " + taskFields + " FROM dns_optimize_tasks WHERE id={:id}").WithContext(ctx).Bind(params).One(&row)
	})
	if err != nil || !claimed {
		return
	}
	task, err := row.task()
	status := "success"
	if err == nil {
		_, err = s.apply(ctx, row.target(), task.Spec, "", id, "scheduler")
	}
	// Provider or access resolver errors may contain upstream details. Persist only a bounded status.
	if err != nil {
		status = "failed"
	}
	_, err = s.app.DB().NewQuery("UPDATE dns_optimize_tasks SET status={:status},last_run={:now},due={:now}+interval*60,lease=0 WHERE id={:id} AND lease={:lease}").Bind(dbx.Params{"id": id, "lease": deadline, "now": time.Now().Unix(), "status": status}).Execute()
	if err != nil {
		s.app.Logger().Error("Could not save DNS optimization task status", "task", id)
	}
}
