package dnsmcp

import (
	"context"
	"database/sql"
	"errors"
	"strconv"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnscert"
)

type deploymentPolicy struct {
	automatic      bool
	followRenewals bool
	rebind         bool
}

func clearDeploymentState(values dbx.Params) {
	values["status"], values["process_id"], values["started"], values["finished"] = 0, "", 0, 0
}

func disableDeploymentAutomation(values dbx.Params) {
	values["automatic"], values["renewal_root"] = false, ""
	values["automatic_approved"] = false
}

func (p deploymentPolicy) apply(app core.App, task deployTask, values dbx.Params) *opError {
	disableDeploymentAutomation(values)
	if !p.automatic {
		if p.followRenewals {
			return invalid
		}
		return nil
	}
	values["automatic"], values["automatic_approved"] = true, true
	if p.followRenewals {
		renewal, err := dnscert.ReadRenewal(app, task.OID)
		if err != nil || !renewal.Enabled || renewal.CurrentOrderID != task.OID {
			return &opError{409, "Select the current order of an enabled renewal schedule"}
		}
		values["renewal_root"] = renewal.RootID
	}
	return nil
}

const dueDeploymentFrom = ` FROM dns_cert_deploy t
	JOIN workflow w ON w.id=t.workflow_id AND w.enabled=1 AND w.hasContent=1
	JOIN access a ON a.id=t.access_id AND a.deleted=''
	LEFT JOIN dns_cert_renewals r ON r.root_id=t.renewal_root AND r.enabled=1
	JOIN dns_cert_orders o ON o.id=COALESCE(r.current_id,t.order_id) AND o.state='issued'
	JOIN certificate c ON c.id=o.certificate_id AND c.deleted='' AND c.isRevoked=0
	WHERE t.active=1 AND t.automatic=1 AND t.automatic_approved=1
	AND unixepoch(c.validityNotBefore)<=unixepoch() AND unixepoch(c.validityNotAfter)>unixepoch()
	AND (t.started=0 OR (t.status=1 AND t.finished>0 AND r.current_id<>t.order_id))
	AND (t.renewal_root='' OR EXISTS(
		SELECT 1 FROM dns_cert_renewal_orders ro WHERE ro.root_id=r.root_id AND ro.order_id=o.id
		AND o.access_id=r.access_id AND o.domain=r.domain))`

// RunCertificateDeployments sends only deployments that an administrator armed.
// An ambiguous write remains stopped until an administrator reconciles the target.
func RunCertificateDeployments(ctx context.Context, app core.App, deploy DeploymentFunc) error {
	if deploy == nil {
		return nil
	}
	s := service{deploy: deploy}
	var cursor string
	for ctx.Err() == nil {
		var ids []string
		if err := app.DB().NewQuery("SELECT t.id" + dueDeploymentFrom + " AND t.id>{:cursor} ORDER BY t.id LIMIT 25").
			Bind(dbx.Params{"cursor": cursor}).WithContext(ctx).Column(&ids); err != nil {
			return errors.New("could not read certificate deployment queue")
		}
		if len(ids) == 0 {
			break
		}
		for _, id := range ids {
			cursor = id
			if ctx.Err() != nil {
				return ctx.Err()
			}
			task, problem := prepareAutomaticDeployment(ctx, app, id)
			if problem == missing || problem == deployConflict {
				continue
			}
			if problem != nil {
				return errors.New(problem.message)
			}
			_, problem = s.deployProcess(ctx, app, object{"id": id, "version": strconv.Itoa(task.Version)}, automaticDeployAccess,
				func(core.App) bool { return ctx.Err() == nil }, false, "schedule")
			if problem == deployDBError {
				return errors.New(problem.message)
			}
		}
	}
	return ctx.Err()
}

func prepareAutomaticDeployment(ctx context.Context, app core.App, id string) (deployTask, *opError) {
	var task deployTask
	var problem *opError
	err := app.RunInTransaction(func(tx core.App) error {
		task, problem = deployTaskRow(tx, "id", id)
		if problem != nil {
			return errors.New(problem.message)
		}
		var nextID string
		err := tx.DB().NewQuery("SELECT o.id" + dueDeploymentFrom + " AND t.id={:id}").
			Bind(dbx.Params{"id": id}).WithContext(ctx).Row(&nextID)
		if errors.Is(err, sql.ErrNoRows) {
			problem = missing
			return errors.New(problem.message)
		}
		if err != nil {
			return err
		}
		if nextID == task.OID {
			return nil
		}
		values := dbx.Params{"order_id": nextID}
		clearDeploymentState(values)
		if problem = deployCAS(tx, task, values, false); problem != nil {
			return errors.New(problem.message)
		}
		task.OID, task.Version = nextID, task.Version+1
		return nil
	})
	if problem == nil && err != nil {
		problem = deployDBError
	}
	return task, problem
}

func automaticDeployAccess(app core.App, task deployTask, _ bool) (certOrder, *opError) {
	var current string
	err := app.DB().NewQuery(`SELECT t.order_id FROM dns_cert_deploy t
		JOIN workflow w ON w.id=t.workflow_id AND w.enabled=1 AND w.hasContent=1
		JOIN access a ON a.id=t.access_id AND a.deleted=''
		LEFT JOIN dns_cert_renewals r ON r.root_id=t.renewal_root AND r.enabled=1
		JOIN dns_cert_orders o ON o.id=t.order_id AND o.state='issued'
		WHERE t.id={:id} AND t.version={:version} AND t.active=1 AND t.automatic=1 AND t.automatic_approved=1
		AND (t.renewal_root='' OR EXISTS(
			SELECT 1 FROM dns_cert_renewal_orders ro WHERE ro.root_id=r.root_id AND ro.order_id=r.current_id
			AND r.current_id=t.order_id AND o.access_id=r.access_id AND o.domain=r.domain))`).
		Bind(dbx.Params{"id": task.ID, "version": task.Version}).Row(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return certOrder{}, deployDBError
	}
	if current != task.OID {
		return certOrder{}, deployConflict
	}
	return certOrderRow(app, current)
}
