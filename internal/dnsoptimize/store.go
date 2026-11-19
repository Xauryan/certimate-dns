package dnsoptimize

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/domain"
)

type taskRow struct {
	ID       string `db:"id"`
	Provider string `db:"provider"`
	Access   string `db:"access"`
	Zone     string `db:"zone"`
	Config   string `db:"config"`
	Interval int    `db:"interval"`
	Enabled  bool   `db:"enabled"`
	Due      int64  `db:"due"`
	LastRun  int64  `db:"last_run"`
	Status   string `db:"status"`
}

func (t taskRow) target() Target { return Target{t.Provider, t.Access, t.Zone} }

type Task struct {
	ID       string `json:"id"`
	Spec     Spec   `json:"spec"`
	Interval int    `json:"interval"`
	Enabled  bool   `json:"enabled"`
	Due      int64  `json:"due"`
	LastRun  int64  `json:"lastRun"`
	Status   string `json:"status"`
}

func (row taskRow) task() (Task, error) {
	var s Spec
	if err := json.Unmarshal([]byte(row.Config), &s); err != nil {
		return Task{}, errors.New("invalid stored optimization task")
	}
	return Task{row.ID, s, row.Interval, row.Enabled, row.Due, row.LastRun, row.Status}, nil
}

const taskFields = "id,provider,access,zone,config,interval,enabled,due,last_run,status"
const scoped = "provider={:provider} AND access={:access} AND zone={:zone}"

func (t Target) params() dbx.Params {
	return dbx.Params{"provider": t.Provider, "access": t.Access, "zone": t.Zone}
}
func oneChange(res sql.Result, err error) error {
	if err != nil {
		return errors.New("optimization task storage operation failed")
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return domain.NewError(409, "task changed, is running, or already exists")
	}
	return nil
}
func SaveDraft(ctx context.Context, app core.App, t Target, s Spec, interval int) (string, error) {
	return SaveConfig(ctx, app, t, s, interval, "")
}
func SaveConfig(ctx context.Context, app core.App, t Target, s Spec, interval int, id string) (string, error) {
	zoneName, err := catalogName(ctx, app, t)
	if err != nil {
		return "", err
	}
	s, err = normalize(t, zoneName, s)
	if err != nil {
		return "", err
	}
	if interval < 10 || interval > 10080 {
		return "", domain.NewError(400, "interval must be between 10 and 10080 minutes")
	}
	data, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	p := t.params()
	p["name"] = s.Name
	p["family"] = s.Family
	p["line"] = s.TargetLine
	p["config"] = string(data)
	p["interval"] = interval
	if id == "" {
		id = rand.Text()
		p["id"] = id
		err = oneChange(app.DB().NewQuery(`INSERT INTO dns_optimize_tasks(id,provider,access,zone,name,family,line,config,interval)
    SELECT {:id},{:provider},{:access},{:zone},{:name},{:family},{:line},{:config},{:interval}
    WHERE (SELECT COUNT(*) FROM dns_optimize_tasks WHERE ` + scoped + `)<100
    ON CONFLICT(provider,access,zone,name,family,line) DO NOTHING`).WithContext(ctx).Bind(p).Execute())
	} else {
		p["id"] = id
		p["now"] = time.Now().Unix()
		err = oneChange(app.DB().NewQuery(`UPDATE dns_optimize_tasks SET name={:name},family={:family},line={:line},config={:config},interval={:interval},status='',last_run=0
   WHERE id={:id} AND ` + scoped + ` AND enabled=0 AND lease<={:now}`).WithContext(ctx).Bind(p).Execute())
	}
	return id, err
}

func listTasks(ctx context.Context, app core.App, t Target) ([]Task, error) {
	var rows []taskRow
	err := app.DB().NewQuery("SELECT " + taskFields + " FROM dns_optimize_tasks WHERE " + scoped + " ORDER BY name,family,line LIMIT 100").WithContext(ctx).Bind(t.params()).All(&rows)
	if err != nil {
		return nil, errors.New("could not read optimization tasks")
	}
	out := make([]Task, 0, len(rows))
	for _, row := range rows {
		task, err := row.task()
		if err != nil {
			return nil, err
		}
		out = append(out, task)
	}
	return out, nil
}
func DeleteDraft(ctx context.Context, app core.App, t Target, id string) error {
	p := t.params()
	p["id"] = id
	p["now"] = time.Now().Unix()
	return oneChange(app.DB().NewQuery("DELETE FROM dns_optimize_tasks WHERE id={:id} AND " + scoped + " AND enabled=0 AND lease<={:now}").WithContext(ctx).Bind(p).Execute())
}

// Both the scheduler and the interactive planner use the catalog's current owner name.
// Some providers have opaque zone IDs. Validate those against the live account binding too.
func catalogName(ctx context.Context, app core.App, t Target) (string, error) {
	var name string
	err := app.DB().NewQuery(`SELECT z.name FROM dnsZone z JOIN dnsAccount a ON z.accountRef=a.id AND a.disabled=0
	JOIN access c ON a.id=c.id AND a.accessRef=c.id AND c.deleted=''
	WHERE c.provider={:provider} AND c.id={:access} AND z.providerZoneId={:zone} AND z.present=1`).WithContext(ctx).Bind(t.params()).Row(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", domain.NewError(404, "zone unavailable; sync the enabled DNS account inventory")
	}
	if err != nil {
		return "", errors.New("could not read DNS account inventory")
	}
	return name, nil
}
