package dnsmcp

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/dnsautomation"
)

type scopedTask struct {
	dnsautomation.Task
	Domain string `db:"domain"`
	DID    string `db:"did"`
}

// The scope join matches both halves of a native target. Provider zone IDs alone
// may be shared by different accounts. Count, lookup and history reuse this CTE.
const taskCTE = `WITH allowed AS (
 SELECT json_extract(value,'$.id') did, json_extract(value,'$.name') domain,
 json_extract(value,'$.accessId') access, json_extract(value,'$.zoneId') zone FROM json_each({:zones})
), tasks AS (
 SELECT t.*,a.did,a.domain FROM dns_automation_tasks t JOIN allowed a ON
 json_extract(t.config,'$.target.accountId')=a.access AND json_extract(t.config,'$.target.zoneId')=a.zone
 WHERE json_extract(t.config,'$.kind')={:kind} AND state<>'archived'
)`

func taskParams(kind string, zones []dnsauth.Zone) dbx.Params {
	raw, _ := json.Marshal(zones)
	return dbx.Params{"kind": kind, "zones": string(raw)}
}
func getScopedTask(e *core.RequestEvent, kind, id string, zones []dnsauth.Zone) (scopedTask, *opError) {
	var t scopedTask
	params := taskParams(kind, zones)
	params["id"] = id
	err := e.App.DB().NewQuery(taskCTE + " SELECT * FROM tasks WHERE id={:id}").Bind(params).WithContext(e.Request.Context()).One(&t)
	if errors.Is(err, sql.ErrNoRows) {
		return t, missing
	}
	if err != nil || json.Unmarshal([]byte(t.Config), &t.Definition) != nil {
		return t, upstream
	}
	return t, nil
}
func flag(b bool) int {
	if b {
		return 1
	}
	return 0
}
func legacyTaskRow(t scopedTask) object {
	d := t.Definition
	rr := strings.TrimSuffix(d.Target.Name, "."+t.Domain)
	if strings.EqualFold(rr, t.Domain) {
		rr = "@"
	}
	row := object{"id": t.ID, "domain": t.Domain, "did": t.DID, "rr": rr, "recordid": d.Target.RecordID, "recordinfo": object{"Type": d.Target.Type}, "active": flag(t.State == "active"), "state": t.State, "version": t.Version, "remark": d.Name}
	if d.Kind == "schedule" {
		row["type"] = flag(d.Schedule.Cycle != "once")
		row["switchtype"] = slices.Index([]string{"update", "enable", "disable", "delete"}, d.Action)
		row["cycle"] = max(0, slices.Index([]string{"daily", "weekly", "monthly"}, d.Schedule.Cycle))
		row["switchdate"] = strconv.Itoa(d.Schedule.Day)
		row["switchtime"], row["timezone"], row["value"] = d.Schedule.At, d.Schedule.Timezone, d.Value
		row["line"] = ""
		if d.Schedule.Proxied != nil {
			row["line"] = strconv.Itoa(flag(*d.Schedule.Proxied))
		}
		return row
	}
	m := d.Monitor
	row["type"] = slices.Index([]string{"observe", "disable", "replace", "standby"}, d.Action)
	row["cdn"], row["proxy"] = flag(d.BackupProxied), 0
	row["main_value"], row["backup_value"], row["checkurl"] = d.Primary, d.Backup, m.Origin
	row["cycle"] = m.FailureThreshold
	if d.Action == "standby" {
		row["cycle"] = m.HealthyLimit
	}
	row["checktype"] = map[string]int{"ping": 0, "tcp": 1, "http": 2, "https": 2}[m.Protocol]
	if m.Protocol == "https" || m.Protocol == "http" {
		row["checkurl"] = m.Protocol + "://" + d.Target.Name + "/"
	}
	row["frequency"], row["tcpport"], row["timeout"] = m.Interval, m.Port, m.Timeout
	row["status"], row["checktimestr"] = flag(t.Position == "backup"), t.LastAt
	return row
}

func listAutomation(e *core.RequestEvent, kind string, zones []dnsauth.Zone, args object) (object, *opError) {
	params := taskParams(kind, zones)
	offset, limit, ok := paging(args)
	if !ok {
		return nil, invalid
	}
	params["limit"], params["offset"] = limit, offset
	q := " FROM tasks WHERE 1=1"
	fieldSQL := map[string]string{"id": "id", "rr": "json_extract(config,'$.target.name')", "recordid": "json_extract(config,'$.target.recordId')", "remark": "json_extract(config,'$.name')", "main_value": "json_extract(config,'$.primary')", "backup_value": "json_extract(config,'$.backup')", "value": "json_extract(config,'$.value')", "active": "(state='active')", "status": "(position='backup')", "checktimestr": "last_at", "frequency": "json_extract(config,'$.monitor.interval')", "switchtime": "json_extract(config,'$.schedule.at')", "stype": "(json_extract(config,'$.schedule.cycle')<>'once')"}
	fields := []string{"rr", "recordid", "main_value", "backup_value", "remark"}
	if kind == "schedule" {
		fields = []string{"rr", "recordid", "value", "remark"}
	}
	n, ok := number(args, "type", 1, 1, len(fields))
	if !ok {
		return nil, invalid
	}
	if kw := str(args, "kw"); kw != "" {
		params["kw"] = kw
		if fields[n-1] == "rr" || fields[n-1] == "remark" {
			q += " AND instr(lower(" + fieldSQL[fields[n-1]] + "),lower({:kw}))>0"
		} else {
			q += " AND " + fieldSQL[fields[n-1]] + "={:kw}"
		}
	}
	for _, key := range []string{"status", "stype"} {
		if str(args, key) != "" {
			v, ok := number(args, key, 0, 0, 1)
			if !ok {
				return nil, invalid
			}
			params[key] = v
			q += " AND " + fieldSQL[key] + "={:" + key + "}"
		}
	}
	sortBy := taskString(args, "sortName", "id")
	order := taskString(args, "sortOrder", "desc")
	if fieldSQL[sortBy] == "" || order != "desc" && order != "asc" {
		return nil, invalid
	}
	out := []object{}
	var total int
	err := e.App.RunInTransaction(func(tx core.App) error {
		if err := tx.DB().NewQuery(taskCTE + " SELECT count(*)" + q).Bind(params).WithContext(e.Request.Context()).Row(&total); err != nil {
			return err
		}
		var rows []scopedTask
		if err := tx.DB().NewQuery(taskCTE + " SELECT *" + q + " ORDER BY " + fieldSQL[sortBy] + " " + order + ",id LIMIT {:limit} OFFSET {:offset}").Bind(params).WithContext(e.Request.Context()).All(&rows); err != nil {
			return err
		}
		for _, t := range rows {
			if err := json.Unmarshal([]byte(t.Config), &t.Definition); err != nil {
				return err
			}
			out = append(out, legacyTaskRow(t))
		}
		return nil
	})
	if err != nil {
		return nil, upstream
	}
	return object{"total": total, "rows": out}, nil
}

// Restrict history to the current task definition. Moving a task to a different
// account must not disclose historical records from its previous zone.
const switchCTE = `, switches AS (
 SELECT r.id,r.task_id,r.finished,
 CASE WHEN (r.action='replace' AND json_extract(r.after_record,'$.content')=json_extract(t.config,'$.backup'))
 OR (r.action='monitor' AND r.outcome='failed')
 OR (r.action='disable' AND json_extract(t.config,'$.action')='disable')
 OR (r.action='enable' AND json_extract(t.config,'$.action')='standby') THEN 1 ELSE 2 END action
 FROM dns_automation_runs r JOIN tasks t ON r.task_id=t.id
 WHERE ((r.action IN ('enable','disable','replace') AND r.outcome='verified') OR (r.action='monitor' AND r.outcome IN ('failed','recovered')))
 AND r.rowid > coalesce((SELECT max(rowid) FROM dns_automation_runs WHERE task_id=t.id AND action='edit'),0)
 AND r.finished >= coalesce((SELECT cutoff FROM dns_monitor_log_cutoffs WHERE task=t.id),0)
)`

func switchReport(e *core.RequestEvent, zones []dnsauth.Zone, action string, args object) (object, *opError) {
	params := taskParams("failover", zones)
	q := " FROM switches WHERE 1=1"
	var t scopedTask
	if action != "overview" {
		var problem *opError
		t, problem = getScopedTask(e, "failover", str(args, "id"), zones)
		if problem != nil {
			return nil, problem
		}
		q += " AND task_id={:id}"
		params["id"] = t.ID
	}
	ctx := e.Request.Context()
	if action == "logs" {
		offset, limit, ok := paging(args)
		if !ok {
			return nil, invalid
		}
		if _, has := args["log_action"]; has {
			v, ok := number(args, "log_action", 0, 0, 2)
			if !ok {
				return nil, invalid
			}
			if v > 0 {
				q += " AND action={:action}"
				params["action"] = v
			}
		}
		params["limit"], params["off"] = limit, offset
		rows := []struct {
			ID     string `db:"id" json:"id"`
			TaskID string `db:"task_id" json:"taskid"`
			Action int    `db:"action" json:"action"`
			Date   int64  `db:"finished" json:"date"`
		}{}
		var total int
		err := e.App.RunInTransaction(func(tx core.App) error {
			if err := tx.DB().NewQuery(taskCTE + switchCTE + " SELECT count(*)" + q).Bind(params).WithContext(ctx).Row(&total); err != nil {
				return err
			}
			return tx.DB().NewQuery(taskCTE + switchCTE + " SELECT *" + q + " ORDER BY finished DESC,id LIMIT {:limit} OFFSET {:off}").Bind(params).WithContext(ctx).All(&rows)
		})
		if err != nil {
			return nil, upstream
		}
		return object{"total": total, "rows": rows}, nil
	}
	var count, fail int
	params["since"] = time.Now().Add(-24 * time.Hour).Unix()
	if err := e.App.DB().NewQuery(taskCTE+switchCTE+" SELECT count(*),coalesce(sum(action=1),0)"+q+" AND finished>={:since}").Bind(params).WithContext(ctx).Row(&count, &fail); err != nil {
		return nil, upstream
	}
	row := object{}
	if action == "info" {
		row = legacyTaskRow(t)
	}
	row["switch_count"], row["fail_count"] = count, fail
	if action == "overview" {
		var active int
		var last int64
		if err := e.App.DB().NewQuery(taskCTE+" SELECT coalesce(sum(state='active'),0),coalesce(max(last_at),0) FROM tasks").Bind(params).WithContext(ctx).Row(&active, &last); err != nil {
			return nil, upstream
		}
		row["active_policies"], row["last_scoped_run"] = active, last
	}
	return object{"code": 0, "data": row}, nil
}

func autoProblem(err error) *opError {
	code, msg := dnsautomation.PublicError(err)
	return &opError{code, msg}
}
func scopedOwner(rr, zone string) (string, bool) {
	name := owner(rr, zone)
	return name, name == zone || strings.HasSuffix(name, "."+zone)
}

func automationDefinition(args object, kind string, z dnsauth.Zone, prior *dnsautomation.Definition) (dnsautomation.Definition, *opError) {
	d := dnsautomation.Definition{Kind: kind}
	if prior != nil {
		d = *prior
	}
	rr := str(args, "rr")
	name, ok := scopedOwner(rr, z.Name)
	if !ok || rr == "" || str(args, "recordid") == "" {
		return d, invalid
	}
	d.Target = dnsautomation.Target{AccountID: z.AccessID, ZoneID: z.ZoneID, RecordID: str(args, "recordid"), Name: name}
	d.Name = str(args, "remark")
	if d.Name == "" {
		d.Name = name
	}
	info, ok := args["recordinfo"].(map[string]any)
	if !ok {
		return d, invalid
	}
	d.Target.Type = strings.ToUpper(str(info, "Type"))
	if d.Target.Type == "" {
		value := str(info, "Value")
		if value == "" {
			return d, invalid
		}
		ip, err := netip.ParseAddr(value)
		d.Target.Type = "CNAME"
		if err == nil {
			d.Target.Type = "AAAA"
			if ip.Is4() {
				d.Target.Type = "A"
			}
		}
	}
	if kind == "schedule" {
		a, ok := number(args, "switchtype", 0, 0, 3)
		if !ok {
			return d, invalid
		}
		d.Action = []string{"update", "enable", "disable", "delete"}[a]
		d.Value = str(args, "value")
		mode, ok := number(args, "type", 0, 0, 1)
		if !ok {
			return d, invalid
		}
		zone := str(args, "timezone")
		if zone == "" {
			zone = "Asia/Shanghai"
		}
		loc, err := time.LoadLocation(zone)
		if err != nil || zone == "Local" {
			return d, invalid
		}
		at := str(args, "switchtime")
		if mode == 0 {
			t, err := time.Parse(time.RFC3339, at)
			if err != nil {
				t, err = time.ParseInLocation("2006-01-02T15:04", at, loc)
			}
			if err != nil {
				return d, invalid
			}
			d.Schedule = dnsautomation.Schedule{Cycle: "once", At: t.Format(time.RFC3339), Timezone: zone}
		} else {
			c, ok := number(args, "cycle", 0, 0, 2)
			if !ok {
				return d, invalid
			}
			day, ok := number(args, "switchdate", 0, 0, 31)
			if !ok {
				return d, invalid
			}
			d.Schedule = dnsautomation.Schedule{Cycle: []string{"daily", "weekly", "monthly"}[c], At: at, Timezone: zone, Day: day}
		}
		if str(args, "line") != "" {
			if z.Provider != "cloudflare" || d.Action != "update" {
				return d, unsupported
			}
			on, ok := taskBool(args, "line")
			if !ok {
				return d, invalid
			}
			d.Schedule.Proxied = &on
		}
	} else {
		if _, has := args["proxy"]; has {
			v, ok := taskBool(args, "proxy")
			if !ok {
				return d, invalid
			}
			if v {
				return d, unsupported
			}
		}
		mode, ok := number(args, "type", 1, 0, 3)
		if !ok {
			return d, invalid
		}
		d.Action = []string{"observe", "disable", "replace", "standby"}[mode]
		if _, has := args["cdn"]; has {
			on, ok := taskBool(args, "cdn")
			if !ok {
				return d, invalid
			}
			if on && (z.Provider != "cloudflare" || d.Action != "replace") {
				return d, unsupported
			}
			d.BackupProxied = on
		}
		d.Primary, d.Backup = str(args, "main_value"), str(args, "backup_value")
		c, ok := number(args, "cycle", 3, 0, 100)
		if !ok {
			return d, invalid
		}
		f, ok := number(args, "frequency", 5, 5, 86400)
		if !ok {
			return d, invalid
		}
		d.Monitor.Interval = f
		if mode == 3 {
			d.Monitor.HealthyLimit = c
			c = 1
		}
		d.Monitor.FailureThreshold, d.Monitor.RecoveryThreshold = c, c
		if mode != 3 {
			check, ok := number(args, "checktype", 1, 0, 2)
			if !ok {
				return d, invalid
			}
			timeout, ok := number(args, "timeout", 2, 1, 15)
			if !ok {
				return d, invalid
			}
			d.Monitor.Timeout = timeout
			urlValue := str(args, "checkurl")
			switch check {
			case 0:
				d.Monitor.Protocol, d.Monitor.Port = "ping", 0
			case 1:
				port, ok := number(args, "tcpport", 80, 1, 65535)
				if !ok {
					return d, invalid
				}
				d.Monitor.Protocol, d.Monitor.Port = "tcp", port
			case 2:
				u, err := url.Parse(urlValue)
				if err != nil || u.Scheme != "https" && u.Scheme != "http" || !strings.EqualFold(u.Host, name) || u.User != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
					return d, unsupported
				}
				d.Monitor.Protocol, d.Monitor.Port = u.Scheme, 80
				if u.Scheme == "https" {
					d.Monitor.Port = 443
				}
				urlValue = taskString(args, "origin", d.Monitor.Origin)
			}
			if urlValue != "" && urlValue != d.Primary {
				if d.Target.Type != "CNAME" {
					return d, unsupported
				}
				d.Monitor.Origin = urlValue
			}
		}
	}
	if err := d.Validate(); err != nil {
		return d, autoProblem(err)
	}
	return d, nil
}

func cardinalStringArgs(row object) object {
	values := make(object, len(row))
	for k, v := range row {
		switch v.(type) {
		case int, int64:
			values[k] = taskInt(v)
		default:
			values[k] = v
		}
	}
	return values
}

func (s service) automationTool(e *core.RequestEvent, kind, action string, args object, zones []dnsauth.Zone, grant scope) (object, *opError) {
	ctx := e.Request.Context()
	switch action {
	case "list":
		return listAutomation(e, kind, zones, args)
	case "overview", "logs", "info":
		result, err := switchReport(e, zones, action, args)
		if err == nil && action == "overview" {
			r := result["data"].(object)
			last := s.automation.LastTick()
			r["run_time"] = last
			r["run_state"] = flag(last > 0 && time.Since(time.Unix(last, 0)) <= 10*time.Second)
		}
		return result, err
	case "add", "edit":
		var prior *dnsautomation.Definition
		version := 0
		if action == "edit" {
			t, err := getScopedTask(e, kind, str(args, "id"), zones)
			if err != nil {
				return nil, err
			}
			values := cardinalStringArgs(legacyTaskRow(t))
			for k, v := range args {
				values[k] = v
			}
			args = values
			prior = &t.Definition
			version = t.Version
		}
		z, ok := findTaskZone(zones, str(args, "did"))
		if !ok {
			return nil, missing
		}
		d, err := automationDefinition(args, kind, z, prior)
		if err != nil {
			return nil, err
		}
		id := str(args, "id")
		if action == "add" {
			t, err := s.automation.Create(ctx, e.Auth.Id, d)
			if err != nil {
				return nil, autoProblem(err)
			}
			id = t.ID
		} else if err := s.automation.Edit(ctx, id, e.Auth.Id, version, d); err != nil {
			return nil, autoProblem(err)
		}
		return taskSuccess(id), nil
	case "clean_logs":
		days, ok := number(args, "days", 0, 1, 36500)
		if !ok || days == 0 {
			return nil, invalid
		}
		params := taskParams(kind, zones)
		params["cutoff"] = time.Now().AddDate(0, 0, -days).Unix()
		_, err := e.App.DB().NewQuery(taskCTE + ` INSERT INTO dns_monitor_log_cutoffs(task,cutoff) SELECT id,{:cutoff} FROM tasks WHERE 1
		ON CONFLICT(task) DO UPDATE SET cutoff=max(cutoff,excluded.cutoff)`).Bind(params).WithContext(ctx).Execute()
		if err != nil {
			return nil, upstream
		}
		return object{"code": 0, "msg": "OK"}, nil
	case "del", "set_active", "batch":
		control := "archive"
		ids := []string{str(args, "id")}
		if action == "set_active" {
			active, ok := taskBool(args, "active")
			if !ok {
				return nil, invalid
			}
			control = "pause"
			if active {
				control = "activate"
			}
		} else if action == "batch" {
			var ok bool
			ids, ok = taskIDs(args["ids"])
			if !ok {
				return nil, invalid
			}
			prefix := "schedule."
			if kind == "failover" {
				prefix = "dmonitor."
			}
			required := prefix + "set_active"
			switch str(args, "act") {
			case "open":
				control = "activate"
			case "close":
				control = "pause"
			case "delete":
				control = "archive"
				required = prefix + "del"
			case "retry":
				if kind != "failover" {
					return nil, invalid
				}
				control = "retry"
			default:
				return nil, invalid
			}
			if !slices.Contains(grant.Actions, required) {
				return nil, denied
			}
		}
		// Check all submitted IDs and their current zones before the first mutation.
		tasks := make([]scopedTask, len(ids))
		for i, id := range ids {
			var err *opError
			tasks[i], err = getScopedTask(e, kind, id, zones)
			if err != nil {
				return nil, err
			}
		}
		for i, t := range tasks {
			if !activeGrant(e) {
				return partial(i, len(tasks), "Interface credential changed")
			}
			if _, err := dnsauth.GetZone(e, t.DID, true); err != nil {
				return partial(i, len(tasks), "Domain grant changed")
			}
			actual := control
			switch control {
			case "activate":
				if t.State == "active" {
					continue
				}
			case "pause":
				if t.State == "draft" || t.State == "paused" || t.State == "completed" {
					continue
				}
			case "retry":
				switch t.State {
				case "review":
					actual = "reconcile"
				case "paused":
					actual = "activate"
				case "active":
					actual = "run"
				default:
					return partial(i, len(tasks), "Task is not retryable")
				}
			}
			if err := s.automation.Control(ctx, t.ID, e.Auth.Id, actual, t.Version); err != nil {
				if len(tasks) == 1 {
					return nil, autoProblem(err)
				}
				return partial(i, len(tasks), autoProblem(err).message)
			}
		}
		return object{"code": 0, "msg": "OK", "completed": len(tasks)}, nil
	default:
		return nil, invalid
	}
}
