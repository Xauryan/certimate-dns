package dnsmcp

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/domain"
)

// Aggregate and history queries start with the live intersection of owner and
// key scope. In particular, two accounts may have identical provider zone IDs.
func (s service) domainReport(e *core.RequestEvent, tool string, args object, grant scope) (object, *opError) {
	zones := make([]dnsauth.Zone, 0, len(grant.Zones))
	for _, id := range grant.Zones {
		z, err := dnsauth.GetZone(e, id, false)
		if errors.Is(err, domain.ErrRecordNotFound) {
			continue
		}
		if err != nil {
			return domainOperationResult(nil, err)
		}
		zones = append(zones, z)
	}
	if tool == "operation_log_query" {
		return domainOperationLogs(e, args, zones)
	}
	return s.domainOverview(e, grant, zones)
}

func (s service) domainOverview(e *core.RequestEvent, grant scope, zones []dnsauth.Zone) (object, *opError) {
	out := object{"domains": len(zones)}
	for _, field := range strings.Fields("tasks certs deploys dmonitor_active dmonitor_state dmonitor_status_0 dmonitor_status_1 optimizeip_active optimizeip_status_1 optimizeip_status_2 certorder_status_3 certorder_status_5 certorder_status_6 certorder_status_7 certdeploy_status_0 certdeploy_status_1 certdeploy_status_2") {
		out[field] = 0
	}
	if !e.HasSuperuserAuth() {
		return out, nil
	}
	ctx := e.Request.Context()
	if slices.Contains(grant.Actions, "dmonitor.read") {
		var total, active, normal, failed int
		err := e.App.DB().NewQuery(taskCTE+` SELECT count(*),`+monitorPositions+` FROM tasks`).Bind(taskParams("failover", zones)).WithContext(ctx).Row(&total, &active, &normal, &failed)
		if err != nil {
			return nil, upstream
		}
		out["tasks"] = total
		out["dmonitor_active"] = active
		out["dmonitor_status_0"] = normal
		out["dmonitor_status_1"] = failed
		if s.automation != nil {
			last := s.automation.LastTick()
			if last > 0 && time.Since(time.Unix(last, 0)) < 10*time.Second {
				out["dmonitor_state"] = 1
			}
		}
	}
	if slices.Contains(grant.Actions, "optimizeip.read") {
		allowed, _ := json.Marshal(zones)
		var active, success, failed int
		err := e.App.DB().NewQuery(`SELECT `+optimizationResults+` FROM dns_optimize_tasks t
    JOIN json_each({:zones}) z ON t.provider=json_extract(z.value,'$.provider') AND t.access=json_extract(z.value,'$.accessId') AND t.zone=json_extract(z.value,'$.zoneId')`).Bind(dbx.Params{"zones": string(allowed)}).WithContext(ctx).Row(&active, &success, &failed)
		if err != nil {
			return nil, upstream
		}
		out["optimizeip_active"] = active
		out["optimizeip_status_1"] = success
		out["optimizeip_status_2"] = failed
	}
	if !grant.Global || !slices.Contains(grant.Actions, "cert.order.read") {
		return out, nil
	}
	zoneIDs := make([]string, 0, len(zones))
	for _, z := range zones {
		zoneIDs = append(zoneIDs, z.ID)
	}
	ids, _ := json.Marshal(zoneIDs)
	accounts, _ := json.Marshal(grant.Accounts)
	params := dbx.Params{"zones": string(ids), "accounts": string(accounts)}
	var count, issued, failed, expiring, expired int
	err := e.App.DB().NewQuery(`SELECT count(*),`+orderResults+certOrdersFrom).Bind(params).WithContext(ctx).Row(&count, &issued, &failed, &expiring, &expired)
	if err != nil {
		return nil, upstream
	}
	out["certs"] = count
	out["certorder_status_3"] = issued
	out["certorder_status_5"] = failed
	out["certorder_status_6"] = expiring
	out["certorder_status_7"] = expired
	if slices.Contains(grant.Actions, "cert.deploy.read") {
		var total, pending, complete, failed int
		err := e.App.DB().NewQuery(`WITH orders AS (SELECT o.id `+certOrdersFrom+`) SELECT count(*),`+deployResults+`
 FROM dns_cert_deploy d JOIN orders o ON o.id=d.order_id JOIN access target ON target.id=d.access_id AND target.deleted=''
 WHERE target.id IN (SELECT value FROM json_each({:accounts}))`).Bind(params).WithContext(ctx).Row(&total, &pending, &complete, &failed)
		if err != nil {
			return nil, upstream
		}
		out["deploys"] = total
		out["certdeploy_status_0"] = pending
		out["certdeploy_status_1"] = complete
		out["certdeploy_status_2"] = failed
	}
	return out, nil
}

type domainLogRow struct {
	ID      string `db:"id" json:"id"`
	Actor   string `db:"actor" json:"uid"`
	Domain  string `db:"domain" json:"domain"`
	Action  string `db:"action" json:"action"`
	Success bool   `db:"success" json:"success"`
	Time    string `db:"created" json:"addtime"`
}

func domainOperationLogs(e *core.RequestEvent, args object, zones []dnsauth.Zone) (object, *opError) {
	offset, limit, ok := paging(args)
	if !ok {
		return nil, invalid
	}
	scopeJSON, _ := json.Marshal(zones)
	params := dbx.Params{"zones": string(scopeJSON), "domain": str(args, "domain"), "kw": str(args, "kw"), "uid": str(args, "uid")}
	// Project only known-safe structured fields. Generic request logs may contain
	// bodies and credentials and have no equivalent scoped DNS resource identity.
	query := ` FROM _logs l JOIN json_each({:zones}) allowed ON json_extract(allowed.value,'$.id')=CASE
 WHEN l.message IN ('DNS interface record operation','DNS interface domain operation') THEN json_extract(l.data,'$.zone')
 WHEN l.message='DNS catalog change' AND json_extract(l.data,'$.action')='edit domain metadata' THEN json_extract(l.data,'$.resource') END
 WHERE coalesce(json_extract(l.data,'$.actor'),'')<>'' AND coalesce(json_extract(l.data,'$.action'),'')<>''
 AND ({:domain}='' OR lower(json_extract(allowed.value,'$.name'))=lower({:domain}))
 AND ({:uid}='' OR json_extract(l.data,'$.actor')={:uid})
 AND ({:kw}='' OR instr(lower(json_extract(l.data,'$.action')),lower({:kw}))>0)`
	if !e.HasSuperuserAuth() {
		params["uid"] = e.Auth.Id
		params["collection"] = e.Auth.Collection().Name
		query += " AND json_extract(l.data,'$.actorCollection')={:collection}"
	}
	var total int
	ctx := e.Request.Context()
	if err := e.App.AuxDB().NewQuery("SELECT count(*)" + query).Bind(params).WithContext(ctx).Row(&total); err != nil {
		return nil, upstream
	}
	rows := []domainLogRow{}
	params["limit"] = limit
	params["offset"] = offset
	err := e.App.AuxDB().NewQuery(`SELECT l.id,json_extract(l.data,'$.actor') actor,json_extract(allowed.value,'$.name') domain,json_extract(l.data,'$.action') action,coalesce(json_extract(l.data,'$.success'),0) success,l.created` + query + " ORDER BY l.created DESC,l.id DESC LIMIT {:limit} OFFSET {:offset}").Bind(params).WithContext(ctx).All(&rows)
	if err != nil {
		return nil, upstream
	}
	return object{"total": total, "rows": rows}, nil
}
