package dnsmcp

import (
	"database/sql"
	"errors"
	"time"

	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnscatalog"
	"github.com/certimate-go/certimate/internal/rest/resp"
)

const monitorPositions = `count(*) FILTER(WHERE state='active'),count(*) FILTER(WHERE position='primary'),count(*) FILTER(WHERE position='backup')`
const optimizationResults = `count(*) FILTER(WHERE enabled=1),count(*) FILTER(WHERE status='success'),count(*) FILTER(WHERE status='failed')`
const orderResults = `count(*) FILTER(WHERE o.state IN ('issued','revoking')),count(*) FILTER(WHERE o.state IN ('failed','cancelled','cancelling')),
 count(*) FILTER(WHERE julianday(cert.validityNotAfter) BETWEEN julianday('now') AND julianday('now','+7 days')),
 count(*) FILTER(WHERE o.state='expired' OR julianday(cert.validityNotAfter)<julianday('now'))`
const deployResults = `count(*) FILTER(WHERE d.status=0),count(*) FILTER(WHERE d.status=1),count(*) FILTER(WHERE d.status=-1)`

type optimizationResult struct {
	At        int64  `db:"last_run" json:"at"`
	Status    string `db:"status" json:"status"`
	Provider  string `db:"provider" json:"provider,omitempty"`
	Access    string `db:"access" json:"access,omitempty"`
	Zone      string `db:"zone" json:"zone,omitempty"`
	CatalogID string `db:"catalogId" json:"catalogId,omitempty"`
}

type adminSummary struct {
	Domains   int `json:"domains"`
	Scheduled int `json:"scheduled"`
	Failover  struct {
		Total     int    `json:"total"`
		Active    int    `json:"active"`
		Primary   int    `json:"primary"`
		Backup    int    `json:"backup"`
		Heartbeat *int64 `json:"heartbeat"`
		Running   *bool  `json:"running"`
	} `json:"failover"`
	Optimization struct {
		Total     int                 `json:"total"`
		Active    int                 `json:"active"`
		Succeeded int                 `json:"succeeded"`
		Failed    int                 `json:"failed"`
		Heartbeat *int64              `json:"heartbeat"`
		Last      *optimizationResult `json:"last"`
	} `json:"optimization"`
	Orders struct {
		Total    int `json:"total"`
		Issued   int `json:"issued"`
		Failed   int `json:"failed"`
		Expiring int `json:"expiring"`
		Expired  int `json:"expired"`
	} `json:"orders"`
	Deployments struct {
		Total     int `json:"total"`
		Pending   int `json:"pending"`
		Succeeded int `json:"succeeded"`
		Failed    int `json:"failed"`
	} `json:"deployments"`
}

func (s service) adminOverview(e *core.RequestEvent) error {
	e.Response.Header().Set("Cache-Control", "no-store")
	ctx := e.Request.Context()
	var summary adminSummary
	domains, err := dnscatalog.CountDomains(ctx, e.App)
	if err != nil {
		return e.InternalServerError("Could not read DNS overview", nil)
	}
	summary.Domains = domains
	f, o, c, d := &summary.Failover, &summary.Optimization, &summary.Orders, &summary.Deployments
	for _, statement := range []struct {
		query string
		cols  []any
	}{
		{`SELECT count(*) FROM dns_automation_tasks WHERE state<>'archived' AND json_extract(config,'$.kind')='schedule'`, []any{&summary.Scheduled}},
		{`SELECT count(*),` + monitorPositions + ` FROM dns_automation_tasks WHERE state<>'archived' AND json_extract(config,'$.kind')='failover'`, []any{&f.Total, &f.Active, &f.Primary, &f.Backup}},
		{`SELECT count(*),` + optimizationResults + ` FROM dns_optimize_tasks`, []any{&o.Total, &o.Active, &o.Succeeded, &o.Failed}},
		{`SELECT count(*),` + orderResults + ` FROM dns_cert_orders o LEFT JOIN certificate cert ON cert.id=o.certificate_id AND cert.deleted='' WHERE o.state<>'deleted'`, []any{&c.Total, &c.Issued, &c.Failed, &c.Expiring, &c.Expired}},
		{`SELECT count(*),` + deployResults + ` FROM dns_cert_deploy d`, []any{&d.Total, &d.Pending, &d.Succeeded, &d.Failed}},
	} {
		if err := e.App.DB().NewQuery(statement.query).WithContext(ctx).Row(statement.cols...); err != nil {
			return e.InternalServerError("Could not read DNS overview", nil)
		}
	}
	var last optimizationResult
	err = e.App.DB().NewQuery(`SELECT t.last_run,t.status,
 CASE WHEN z.id IS NOT NULL THEN c.provider ELSE '' END AS provider,
 coalesce(z.accountRef,'') AS access,coalesce(z.providerZoneId,'') AS zone,coalesce(z.id,'') AS catalogId
 FROM dns_optimize_tasks t
 LEFT JOIN dnsAccount a ON a.id=t.access AND a.accessRef=t.access AND a.disabled=0
 LEFT JOIN access c ON c.id=a.accessRef AND c.provider=t.provider AND c.deleted='' AND c.reserve=''
 LEFT JOIN dnsZone z ON z.accountRef=c.id AND z.providerZoneId=t.zone AND z.present=1
 WHERE t.last_run>0 AND t.status IN ('success','failed') ORDER BY t.last_run DESC,t.id LIMIT 1`).WithContext(ctx).One(&last)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return e.InternalServerError("Could not read DNS overview", nil)
	}
	if err == nil {
		o.Last = &last
	}
	if s.automation != nil {
		if tick := s.automation.LastTick(); tick > 0 {
			f.Heartbeat = &tick
			age := time.Since(time.Unix(tick, 0))
			running := age >= 0 && age < 10*time.Second
			f.Running = &running
		}
	}
	if s.optimize != nil {
		if tick := s.optimize.LastTick(); tick > 0 {
			o.Heartbeat = &tick
		}
	}
	return resp.Ok(e, summary)
}
