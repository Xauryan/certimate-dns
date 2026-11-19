package dnsmigrate

import (
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pocketbase/dbx"

	"github.com/certimate-go/certimate/internal/dnsautomation"
	"github.com/certimate-go/certimate/internal/dnsoptimize"
)

// Consent links to local objects. It neither contacts a provider nor changes
// task configuration, execution state or leases.
func (p *planner) planTaskPromotion(b Promotion, source Item, previouslyApplied bool) (promotionWork, error) {
	if b.Role != "" || (len(b.AdditionalTargets) != 0 && source.Kind != "optimizeip") {
		return promotionWork{Conflict: "unexpected task or alias binding options"}, nil
	}
	if source.Kind == "domain_alias" {
		a := source.details.(Related)
		parent, ok := p.sourceItem("domain", a.ParentID)
		alias, err := canonicalName(a.Domain, false)
		if !ok || parent.AccountID == "" || parent.ProviderZone == "" || parent.Action == "conflict" || parent.Target != b.TargetID || err != nil || alias == parent.details.(Zone).Name {
			return promotionWork{Conflict: "alias must reference its imported parent zone and a distinct domain name"}, nil
		}
		// The source alias has no offline native provider object. The promotion
		// records only the parent zone association for the administrator to review.
		return promotionWork{}, nil
	}
	t := source.details.(Task)
	parent, ok := p.sourceItem("domain", t.ZoneID)
	if !ok || parent.AccountID == "" || parent.ProviderZone == "" || parent.Action == "conflict" {
		return promotionWork{Conflict: "task zone has no verified native identity"}, nil
	}
	z := parent.details.(Zone)
	name := z.Name
	if t.RR != "@" {
		name = t.RR + "." + name
	}
	if t.Kind == "optimizeip" {
		return p.planOptimizationLinks(b, *t.Optimize, parent, name, previouslyApplied)
	}
	var row struct {
		Config string `db:"config"`
		State  string `db:"state"`
		Lease  string `db:"lease"`
	}
	err := p.db.NewQuery("SELECT config,state,lease FROM dns_automation_tasks WHERE id={:id}").Bind(dbx.Params{"id": b.TargetID}).WithContext(p.ctx).One(&row)
	if errors.Is(err, sql.ErrNoRows) {
		return promotionWork{Conflict: "automation task does not exist"}, nil
	}
	if err != nil {
		return promotionWork{}, err
	}
	if row.State == "archived" || !previouslyApplied && (row.Lease != "" || row.State != "draft" && row.State != "paused") {
		return promotionWork{Conflict: "select an unleased draft or paused automation task"}, nil
	}
	var d dnsautomation.Definition
	if json.Unmarshal([]byte(row.Config), &d) != nil || d.Target.AccountID != parent.AccountID || d.Target.ZoneID != parent.ProviderZone || !sameDNSName(d.Target.Name, name) || d.Target.RecordID == "" || (t.Record != "" && d.Target.RecordID != t.Record) {
		return promotionWork{Conflict: "automation account, zone, record name or ID differs"}, nil
	}
	if t.Kind == "sctask" {
		if d.Kind != "schedule" || !matchesSourceSchedule(*t.Schedule, d, p.manifest.Timezone) {
			return promotionWork{Conflict: "scheduled task action, value, proxy setting or recurrence differs"}, nil
		}
	} else if t.Kind != "dmtask" || d.Kind != "failover" || !matchesSourceMonitor(*t.Monitor, d) {
		return promotionWork{Conflict: "monitor action, record or probe configuration differs"}, nil
	}
	return promotionWork{}, nil
}

func sameDNSName(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

func matchesSourceSchedule(s Schedule, d dnsautomation.Definition, timezone string) bool {
	actions := []string{"update", "enable", "disable", "delete"}
	if s.Action < 0 || s.Action >= len(actions) || d.Action != actions[s.Action] {
		return false
	}
	if d.Action == "update" {
		if d.Target.Type != recordType(s.Value) || !sameDNSName(d.Value, s.Value) {
			return false
		}
		proxy := d.Schedule.Proxied
		if s.ProxyLine == "" && proxy != nil || s.ProxyLine != "" && (proxy == nil || *proxy != (s.ProxyLine == "1")) {
			return false
		}
	}
	if s.Mode == 0 {
		loc, err := time.LoadLocation(timezone)
		if err != nil {
			return false
		}
		expected, err := time.ParseInLocation("2006-01-02T15:04", strings.Replace(s.At, " ", "T", 1), loc)
		target, otherErr := time.Parse(time.RFC3339, d.Schedule.At)
		return d.Schedule.Cycle == "once" && err == nil && otherErr == nil && expected.Equal(target)
	}
	cycles := []string{"daily", "weekly", "monthly"}
	if s.Mode != 1 || s.Cycle < 0 || s.Cycle >= len(cycles) || cycles[s.Cycle] != d.Schedule.Cycle || d.Schedule.Timezone != timezone || d.Schedule.At != s.At {
		return false
	}
	if s.Cycle == 0 {
		return true
	}
	day, err := strconv.Atoi(s.Day)
	return err == nil && day == d.Schedule.Day
}

func matchesSourceMonitor(f Monitor, d dnsautomation.Definition) bool {
	actions := []string{"observe", "disable", "replace", "standby"}
	if f.Action < 0 || f.Action >= len(actions) || actions[f.Action] != d.Action || f.Frequency != d.Monitor.Interval {
		return false
	}
	if f.Action == 3 {
		return d.Monitor.HealthyLimit == f.Cycles
	}
	if f.Proxy || d.Target.Type != recordType(f.Primary) || !sameDNSName(f.Primary, d.Primary) || d.BackupProxied != f.CDN || f.Cycles != d.Monitor.FailureThreshold || f.Cycles != d.Monitor.RecoveryThreshold || f.Timeout != d.Monitor.Timeout {
		return false
	}
	if f.Action == 2 && !sameDNSName(f.Backup, d.Backup) {
		return false
	}
	switch f.Protocol {
	case 0:
		return d.Monitor.Protocol == "ping"
	case 1:
		return d.Monitor.Protocol == "tcp" && f.Port == d.Monitor.Port
	case 2:
		return f.HasURL && (d.Monitor.Protocol == "http" || d.Monitor.Protocol == "https")
	default:
		return false
	}
}

func (p *planner) planOptimizationLinks(b Promotion, o Optimize, parent Item, name string, previouslyApplied bool) (promotionWork, error) {
	cdns := []string{"", "cloudflare", "cloudfront", "gcore", "edgeone"}
	if o.CDN < 1 || o.CDN >= len(cdns) || o.Mode < 0 || o.Mode > 1 || o.Count < 1 || o.Count > 50 {
		return promotionWork{Conflict: "unsupported source optimization configuration"}, nil
	}
	families := strings.Split(o.Family, ",")
	want := make(map[[2]string]string)
	for _, f := range families {
		for _, line := range []string{"CT", "CU", "CM"} {
			target := line
			if o.Mode == 1 && line == "CT" {
				target = "DEF"
			}
			want[[2]string{f, line}] = target
		}
	}
	if len(b.AdditionalTargets)+1 != len(want) {
		return promotionWork{Conflict: "select a complete task set for the source address families and lines"}, nil
	}
	ranks := make([]int, o.Count)
	for j := range ranks {
		ranks[j] = j + 1
	}
	for _, id := range append([]string{b.TargetID}, b.AdditionalTargets...) {
		var row struct {
			Config  string `db:"config"`
			Enabled bool   `db:"enabled"`
			Lease   int64  `db:"lease"`
			Name    string `db:"name"`
			Family  string `db:"family"`
			Line    string `db:"line"`
		}
		err := p.db.NewQuery(`SELECT o.config,o.enabled,o.lease,o.name,o.family,o.line FROM dns_optimize_tasks o
			JOIN access a ON a.id=o.access AND a.provider=o.provider AND a.deleted=''
			WHERE o.id={:id} AND o.access={:account} AND o.zone={:zone}`).Bind(dbx.Params{"id": id, "account": parent.AccountID, "zone": parent.ProviderZone}).WithContext(p.ctx).One(&row)
		if errors.Is(err, sql.ErrNoRows) {
			return promotionWork{Conflict: "optimization task is missing or belongs to another account or zone"}, nil
		}
		if err != nil {
			return promotionWork{}, err
		}
		if !previouslyApplied && (row.Enabled || row.Lease != 0) {
			return promotionWork{Conflict: "select disabled, unleased optimization tasks"}, nil
		}
		var spec dnsoptimize.Spec
		if json.Unmarshal([]byte(row.Config), &spec) != nil || !sameDNSName(name, spec.Name) || !sameDNSName(row.Name, spec.Name) || row.Family != spec.Family || row.Line != spec.TargetLine || o.TTL != spec.TTL || cdns[o.CDN] != spec.CDN || !slices.Equal(ranks, spec.Ranks) {
			return promotionWork{Conflict: "optimization record, CDN, TTL or rank list differs"}, nil
		}
		key := [2]string{spec.Family, spec.SourceLine}
		line, ok := want[key]
		if !ok || line != spec.TargetLine {
			return promotionWork{Conflict: "duplicate or mismatched optimization family or line"}, nil
		}
		delete(want, key)
	}
	return promotionWork{}, nil
}
