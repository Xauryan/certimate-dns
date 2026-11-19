package dnsoptimize

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/certimate-go/certimate/internal/domain"
	"github.com/pocketbase/pocketbase/core"
)

func (s *Service) Preview(ctx context.Context, t Target, spec Spec) (Plan, error) {
	_, plan, err := s.preview(ctx, t, spec)
	return plan, err
}
func (s *Service) ListTasks(ctx context.Context, t Target) ([]Task, error) {
	if err := s.authorize(ctx, t); err != nil {
		return nil, err
	}
	return listTasks(ctx, s.app, t)
}
func (s *Service) SaveTask(ctx context.Context, t Target, spec Spec, interval int, id string) (string, error) {
	return SaveConfig(ctx, s.app, t, spec, interval, id)
}
func (s *Service) RemoveTask(ctx context.Context, t Target, id string) error {
	if err := s.authorize(ctx, t); err != nil {
		return err
	}
	return DeleteDraft(ctx, s.app, t, id)
}

func (s *Service) readTask(ctx context.Context, t Target, id string) (taskRow, error) {
	p := t.params()
	p["id"] = id
	var row taskRow
	err := s.app.DB().NewQuery("SELECT " + taskFields + " FROM dns_optimize_tasks WHERE id={:id} AND " + scoped).WithContext(ctx).Bind(p).One(&row)
	if errors.Is(err, sql.ErrNoRows) {
		return row, domain.ErrRecordNotFound
	}
	if err != nil {
		return row, errors.New("could not read optimization task")
	}
	return row, nil
}

// ReviewTask prepares the conditional update separately so multiple reviewed lines
// can be enabled or paused in one transaction. A changed configuration or lease invalidates the review.
func (s *Service) ReviewTask(ctx context.Context, t Target, id string, enabled bool, digest string) (func(core.App) error, error) {
	if err := s.authorize(ctx, t); err != nil {
		return nil, err
	}
	row, err := s.readTask(ctx, t, id)
	if err != nil {
		return nil, err
	}
	if enabled {
		task, err := row.task()
		if err != nil {
			return nil, err
		}
		plan, err := s.Preview(ctx, t, task.Spec)
		if err != nil {
			return nil, err
		}
		if plan.Digest != digest {
			return nil, domain.NewError(409, "preview the saved task before enabling its schedule")
		}
	}
	return func(tx core.App) error {
		if _, err := catalogName(ctx, tx, t); err != nil {
			return err
		}
		p := t.params()
		p["id"] = id
		p["now"] = time.Now().Unix()
		p["config"] = row.Config
		p["interval"] = row.Interval
		p["enabled"] = enabled
		p["oldEnabled"] = row.Enabled
		return oneChange(tx.DB().NewQuery("UPDATE dns_optimize_tasks SET enabled={:enabled},due=CASE WHEN {:enabled} THEN {:now}+interval*60 ELSE 0 END WHERE " + scoped + " AND id={:id} AND config={:config} AND interval={:interval} AND enabled={:oldEnabled} AND lease<={:now}").WithContext(ctx).Bind(p).Execute())
	}, nil
}

func (s *Service) SetEnabled(ctx context.Context, t Target, id string, enabled bool, digest string) error {
	change, err := s.ReviewTask(ctx, t, id, enabled, digest)
	if err != nil {
		return err
	}
	return s.app.RunInTransaction(change)
}

func (s *Service) RunTask(ctx context.Context, t Target, id, actor, digest string) (Plan, error) {
	if actor == "" || len(digest) != 64 {
		return Plan{}, domain.ErrInvalidParams
	}
	if err := s.authorize(ctx, t); err != nil {
		return Plan{}, err
	}
	if err := s.lock(ctx); err != nil {
		return Plan{}, err
	}
	defer s.unlock()
	row, err := s.readTask(ctx, t, id)
	if err != nil {
		return Plan{}, err
	}
	task, err := row.task()
	if err != nil {
		return Plan{}, err
	}
	now := time.Now()
	deadline := now.Add(3 * time.Minute).Unix()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	p := t.params()
	p["id"], p["now"], p["lease"], p["config"] = id, now.Unix(), deadline, row.Config
	err = oneChange(s.app.DB().NewQuery("UPDATE dns_optimize_tasks SET lease={:lease} WHERE " + scoped + " AND id={:id} AND config={:config} AND lease<={:now}").WithContext(ctx).Bind(p).Execute())
	if err != nil {
		return Plan{}, err
	}
	plan, runErr := s.apply(ctx, t, task.Spec, digest, id, actor)
	p["status"] = "success"
	if runErr != nil {
		p["status"] = "failed"
	}
	p["now"] = time.Now().Unix()
	updateErr := oneChange(s.app.DB().NewQuery("UPDATE dns_optimize_tasks SET last_run={:now},status={:status},lease=0 WHERE " + scoped + " AND id={:id} AND lease={:lease}").Bind(p).Execute())
	if updateErr != nil {
		return Plan{}, updateErr
	}
	return plan, runErr
}
