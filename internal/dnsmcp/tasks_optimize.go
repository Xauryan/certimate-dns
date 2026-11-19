package dnsmcp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/dnsoptimize"
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

type optimizeConfig struct {
	RR       string `json:"rr"`
	Mode     int    `json:"type"`
	CDN      int    `json:"cdn_type"`
	Family   string `json:"ip_type"`
	Count    int    `json:"recordnum"`
	TTL      int    `json:"ttl"`
	Remark   string `json:"remark"`
	Source   string `json:"source"`
	Interval int    `json:"interval"`
}
type optimizeGroup struct {
	ID       string            `db:"id"`
	Zone     string            `db:"zone"`
	Config   string            `db:"config"`
	Children string            `db:"children"`
	Native   *dnsoptimize.Spec `db:"-"`
}

func (g optimizeGroup) parse() (optimizeConfig, []string, error) {
	var c optimizeConfig
	var children []string
	err := json.Unmarshal([]byte(g.Config), &c)
	if err == nil {
		err = json.Unmarshal([]byte(g.Children), &children)
	}
	if len(children) < 1 || len(children) > 8 {
		err = domain.ErrInvalidParams
	}
	return c, children, err
}
func (c optimizeConfig) values() object {
	return object{"rr": c.RR, "type": c.Mode, "cdn_type": c.CDN, "ip_type": c.Family, "recordnum": c.Count, "ttl": c.TTL, "remark": c.Remark, "source": c.Source, "interval": c.Interval}
}
func optimizationConfig(args object, z dnsauth.Zone) (optimizeConfig, []dnsoptimize.Spec, *opError) {
	var c optimizeConfig
	c.RR = str(args, "rr")
	fqdn, ok := scopedOwner(c.RR, z.Name)
	if !ok {
		return c, nil, invalid
	}
	c.Mode, ok = number(args, "type", 0, 0, 1)
	if !ok {
		return c, nil, invalid
	}
	c.CDN, ok = number(args, "cdn_type", 1, 1, 4)
	if !ok {
		return c, nil, invalid
	}
	c.Family = taskString(args, "ip_type", "v4")
	if c.Family != "v4" && c.Family != "v6" && c.Family != "v4,v6" {
		return c, nil, invalid
	}
	c.Count, ok = number(args, "recordnum", 2, 1, 50)
	if !ok {
		return c, nil, invalid
	}
	c.TTL, ok = number(args, "ttl", 600, 1, 604800)
	if !ok {
		return c, nil, invalid
	}
	c.Interval, ok = number(args, "interval", 60, 10, 10080)
	if !ok {
		return c, nil, invalid
	}
	c.Remark = str(args, "remark")
	if len(c.Remark) > 255 {
		return c, nil, invalid
	}
	source := "wetest"
	if c.CDN == 1 && c.Family == "v4" {
		source = "xingpingcn"
	}
	c.Source = taskString(args, "source", source)
	cdn := []string{"", "cloudflare", "cloudfront", "gcore", "edgeone"}[c.CDN]
	ranks := make([]int, c.Count)
	for i := range ranks {
		ranks[i] = i + 1
	}
	var specs []dnsoptimize.Spec
	for _, family := range strings.Split(c.Family, ",") {
		for _, line := range []string{"CT", "CU", "CM"} {
			target := line
			if c.Mode == 1 && line == "CT" {
				target = "DEF"
			}
			specs = append(specs, dnsoptimize.Spec{Name: fqdn, Source: c.Source, CDN: cdn, Family: family, SourceLine: line, TargetLine: target, TTL: c.TTL, Ranks: ranks})
		}
	}
	return c, specs, nil
}
func optTarget(z dnsauth.Zone) dnsoptimize.Target {
	return dnsoptimize.Target{Provider: z.Provider, Access: z.AccessID, Zone: z.ZoneID}
}
func optProblem(err error) *opError {
	var known *domain.Error
	if errors.As(err, &known) && known.Code >= 400 && known.Code < 500 {
		return &opError{known.Code, known.Msg}
	}
	return upstream
}
func listOptimizeGroups(e *core.RequestEvent, zones []dnsauth.Zone, id string) ([]optimizeGroup, *opError) {
	ids := make([]string, 0, len(zones))
	for _, z := range zones {
		ids = append(ids, z.ID)
	}
	raw, _ := json.Marshal(ids)
	var groups []optimizeGroup
	err := e.App.DB().NewQuery("SELECT id,zone,config,children FROM dns_optimize_groups WHERE zone IN (SELECT value FROM json_each({:zones})) AND ({:id}='' OR id={:id}) ORDER BY id").WithContext(e.Request.Context()).Bind(dbx.Params{"id": id, "zones": string(raw)}).All(&groups)
	if err != nil {
		return nil, upstream
	}
	// Include tasks created by the native console or imported before group support.
	// A group child appears once, through its group. Scope standalone rows by the
	// complete provider/account/zone tuple before inspecting their configuration.
	rawZones, _ := json.Marshal(zones)
	var singles []struct {
		ID       string `db:"id"`
		Zone     string `db:"zone"`
		Config   string `db:"config"`
		Name     string `db:"name"`
		Interval int    `db:"interval"`
	}
	err = e.App.DB().NewQuery(`SELECT t.id, json_extract(a.value,'$.id') zone,json_extract(a.value,'$.name') name,t.config,t.interval
	FROM dns_optimize_tasks t JOIN json_each({:zones}) a ON t.provider=json_extract(a.value,'$.provider')
	AND t.access=json_extract(a.value,'$.accessId') AND t.zone=json_extract(a.value,'$.zoneId')
	WHERE ({:id}='' OR t.id={:id}) AND NOT EXISTS (SELECT 1 FROM dns_optimize_groups g JOIN json_each(g.children) j
	ON j.value=t.id WHERE g.zone=json_extract(a.value,'$.id'))`).Bind(dbx.Params{"id": id, "zones": string(rawZones)}).WithContext(e.Request.Context()).All(&singles)
	if err != nil {
		return nil, upstream
	}
	for _, row := range singles {
		var spec dnsoptimize.Spec
		if json.Unmarshal([]byte(row.Config), &spec) != nil {
			return nil, upstream
		}
		rr := strings.TrimSuffix(spec.Name, "."+row.Name)
		if rr == row.Name {
			rr = "@"
		}
		c := optimizeConfig{RR: rr, Mode: flag(spec.TargetLine == "DEF"), CDN: slices.Index([]string{"", "cloudflare", "cloudfront", "gcore", "edgeone"}, spec.CDN), Family: spec.Family, Count: len(spec.Ranks), TTL: spec.TTL, Source: spec.Source, Interval: row.Interval}
		config, _ := json.Marshal(c)
		children, _ := json.Marshal([]string{row.ID})
		groups = append(groups, optimizeGroup{ID: row.ID, Zone: row.Zone, Config: string(config), Children: string(children), Native: &spec})
	}
	return groups, nil
}
func optChildSet(e *core.RequestEvent, z dnsauth.Zone, children []string) ([]dnsoptimize.Task, *opError) {
	// Check each child's live binding as well as the group's domain. An edited or
	// missing native line invalidates the group operation.
	raw, _ := json.Marshal(children)
	rows := []struct {
		ID       string `db:"id"`
		Config   string `db:"config"`
		Enabled  bool   `db:"enabled"`
		Status   string `db:"status"`
		Last     int64  `db:"last_run"`
		Interval int    `db:"interval"`
	}{}
	err := e.App.DB().NewQuery(`SELECT id,config,enabled,status,last_run,interval FROM dns_optimize_tasks WHERE provider={:p} AND access={:a} AND zone={:z} AND id IN (SELECT value FROM json_each({:ids}))`).Bind(dbx.Params{"p": z.Provider, "a": z.AccessID, "z": z.ZoneID, "ids": string(raw)}).WithContext(e.Request.Context()).All(&rows)
	if err != nil {
		return nil, upstream
	}
	if len(rows) != len(children) {
		return nil, &opError{409, "Grouped optimization task changed"}
	}
	byID := make(map[string]dnsoptimize.Task, len(rows))
	for _, r := range rows {
		var spec dnsoptimize.Spec
		if json.Unmarshal([]byte(r.Config), &spec) != nil {
			return nil, upstream
		}
		byID[r.ID] = dnsoptimize.Task{ID: r.ID, Spec: spec, Enabled: r.Enabled, Status: r.Status, LastRun: r.Last, Interval: r.Interval}
	}
	out := make([]dnsoptimize.Task, 0, len(rows))
	for _, id := range children {
		t, ok := byID[id]
		if !ok {
			return nil, missing
		}
		out = append(out, t)
	}
	return out, nil
}

func (s service) optimizeTool(e *core.RequestEvent, action string, args object, zones []dnsauth.Zone) (object, *opError) {
	if s.optimize == nil {
		return nil, unsupported
	}
	ctx := e.Request.Context()
	if len(zones) == 0 {
		return nil, denied
	}
	if action == "api_balance" {
		b, err := s.optimize.Quota(ctx, taskString(args, "source", "xingpingcn"))
		if err != nil {
			return nil, optProblem(err)
		}
		return object{"code": 0, "data": b}, nil
	}
	id := str(args, "id")
	if action != "list" && action != "add" && id == "" {
		return nil, invalid
	}
	groups, problem := listOptimizeGroups(e, zones, id)
	if problem != nil {
		return nil, problem
	}
	if action == "list" {
		out := []object{}
		for _, g := range groups {
			z, _ := findTaskZone(zones, g.Zone)
			c, children, err := g.parse()
			if err != nil {
				return nil, upstream
			}
			row := c.values()
			if g.Native != nil {
				row["sourceLine"], row["targetLine"], row["ranks"], row["replaceCname"] = g.Native.SourceLine, g.Native.TargetLine, g.Native.Ranks, g.Native.ReplaceCNAME
			}
			row["id"], row["did"], row["domain"] = g.ID, z.ID, z.Name
			items, err2 := optChildSet(e, z, children)
			row["status"], row["active"], row["updatetime"] = 0, 0, int64(0)
			if err2 != nil {
				if err2.status != 409 {
					return nil, err2
				}
				row["status"] = 2
			} else {
				allActive, allSuccess := true, true
				for _, t := range items {
					allActive = allActive && t.Enabled
					allSuccess = allSuccess && t.Status == "success"
					if t.Status == "failed" {
						row["status"] = 2
					}
					if t.LastRun > row["updatetime"].(int64) {
						row["updatetime"] = t.LastRun
					}
				}
				if allSuccess {
					row["status"] = 1
				}
				row["active"] = flag(allActive)
			}
			if status := str(args, "status"); status != "" && status != taskInt(row["status"]) {
				continue
			}
			if containsTaskFilter(row, args, []string{"rr", "remark"}) {
				out = append(out, row)
			}
		}
		return taskPage(out, args, "id", "rr", "cdn_type", "recordnum", "ip_type", "active", "updatetime", "status")
	}
	var g optimizeGroup
	var oldZone dnsauth.Zone
	var children []string
	var prev optimizeConfig
	var err error
	if action != "add" {
		if len(groups) != 1 {
			return nil, missing
		}
		g = groups[0]
		oldZone, _ = findTaskZone(zones, g.Zone)
		prev, children, err = g.parse()
		if err != nil {
			return nil, upstream
		}
	}
	params := dbx.Params{"id": id, "old": g.Children, "oldConfig": g.Config}
	if action == "add" || action == "edit" || action == "del" {
		var z dnsauth.Zone
		var c optimizeConfig
		var specs []dnsoptimize.Spec
		if action != "del" {
			values := args
			if action == "edit" {
				values = cardinalStringArgs(prev.values())
				values["did"] = oldZone.ID
				for k, v := range args {
					values[k] = v
				}
			}
			var ok bool
			z, ok = findTaskZone(zones, str(values, "did"))
			if !ok {
				return nil, missing
			}
			c, specs, problem = optimizationConfig(values, z)
			if problem != nil {
				return nil, problem
			}
		}
		if g.Native != nil {
			// Native single-line tasks retain their line, rank order and immutable
			// identity unless the caller explicitly supplies a supported change.
			if action == "del" {
				if err := s.optimize.RemoveTask(ctx, optTarget(oldZone), id); err != nil {
					return nil, optProblem(err)
				}
				return taskSuccess(id), nil
			}
			if z.ID != oldZone.ID || c.Mode != prev.Mode || strings.Contains(c.Family, ",") || c.Remark != "" {
				return nil, unsupported
			}
			spec := specs[0]
			spec.SourceLine, spec.TargetLine, spec.ReplaceCNAME = g.Native.SourceLine, g.Native.TargetLine, g.Native.ReplaceCNAME
			if _, has := args["recordnum"]; !has {
				spec.Ranks = g.Native.Ranks
			}
			if _, err := s.optimize.SaveTask(ctx, optTarget(z), spec, c.Interval, id); err != nil {
				return nil, optProblem(err)
			}
			return taskSuccess(id), nil
		}
		if action == "add" {
			id = rand.Text()
			params["id"] = id
		}
		err = e.App.RunInTransaction(func(tx core.App) error {
			if !activeGrantIn(e, tx) {
				return domain.NewError(403, "Interface credential changed")
			}
			if action != "add" {
				res, err := tx.DB().NewQuery("DELETE FROM dns_optimize_groups WHERE id={:id} AND config={:oldConfig} AND children={:old}").Bind(params).WithContext(ctx).Execute()
				if err != nil {
					return err
				}
				n, err := res.RowsAffected()
				if err != nil {
					return err
				}
				if n != 1 {
					return domain.NewError(409, "Optimization group changed")
				}
				for _, child := range children {
					if err := dnsoptimize.DeleteDraft(ctx, tx, optTarget(oldZone), child); err != nil {
						return err
					}
				}
			}
			if action == "del" {
				return nil
			}
			newIDs := make([]string, 0, len(specs))
			for _, spec := range specs {
				child, err := dnsoptimize.SaveConfig(ctx, tx, optTarget(z), spec, c.Interval, "")
				if err != nil {
					return err
				}
				newIDs = append(newIDs, child)
			}
			raw, _ := json.Marshal(c)
			ids, _ := json.Marshal(newIDs)
			params["zone"], params["config"], params["children"] = z.ID, string(raw), string(ids)
			_, err := tx.DB().NewQuery("INSERT INTO dns_optimize_groups(id,zone,config,children) VALUES({:id},{:zone},{:config},{:children})").Bind(params).WithContext(ctx).Execute()
			return err
		})
		if err != nil {
			return nil, optProblem(err)
		}
		return taskSuccess(id), nil
	}
	if action != "run" && action != "set_active" {
		return nil, invalid
	}
	enabled := true
	if action == "set_active" {
		var ok bool
		enabled, ok = taskBool(args, "active")
		if !ok {
			return nil, invalid
		}
	}
	items, problem := optChildSet(e, oldZone, children)
	if problem != nil {
		return nil, problem
	}
	target := optTarget(oldZone)
	digests := make([]string, len(children))
	if enabled {
		plans := make([]dnsoptimize.Plan, 0, len(items))
		for i, t := range items {
			p, err := s.optimize.Preview(ctx, target, t.Spec)
			if err != nil {
				return nil, optProblem(err)
			}
			plans = append(plans, p)
			digests[i] = p.Digest
		}
		// Bind the confirmation to group membership and every independently previewed line.
		data, _ := json.Marshal([]any{id, action, children, digests})
		sum := sha256.Sum256(data)
		confirmation := hex.EncodeToString(sum[:])
		if preview, _ := taskBool(args, "preview"); preview {
			return object{"code": 0, "data": object{"digest": confirmation, "plans": plans}}, nil
		}
		if str(args, "digest") != confirmation {
			return nil, &opError{409, "Request preview=true and confirm the digest before applying the group"}
		}
	}
	if action == "run" {
		for i, child := range children {
			if !activeGrant(e) {
				return partial(i, len(children), "Interface credential changed")
			}
			if _, err := dnsauth.GetZone(e, oldZone.ID, true); err != nil {
				return partial(i, len(children), "Domain grant changed")
			}
			if _, err := s.optimize.RunTask(ctx, target, child, e.Auth.Id, digests[i]); err != nil {
				return partial(i, len(children), optProblem(err).message)
			}
		}
	} else {
		var changes []func(core.App) error
		for i, child := range children {
			change, err := s.optimize.ReviewTask(ctx, target, child, enabled, digests[i])
			if err != nil {
				return nil, optProblem(err)
			}
			changes = append(changes, change)
		}
		err = e.App.RunInTransaction(func(tx core.App) error {
			if !activeGrantIn(e, tx) {
				return domain.NewError(403, "Interface credential changed")
			}
			if g.Native != nil {
				return changes[0](tx)
			}
			var stored string
			if err := tx.DB().NewQuery("SELECT children FROM dns_optimize_groups WHERE id={:id}").Bind(params).WithContext(ctx).Row(&stored); err != nil {
				return err
			}
			var current []string
			if json.Unmarshal([]byte(stored), &current) != nil || !slices.Equal(current, children) {
				return domain.NewError(409, "Optimization group changed")
			}
			for _, change := range changes {
				if err := change(tx); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return nil, optProblem(err)
		}
	}
	return taskSuccess(id), nil
}
