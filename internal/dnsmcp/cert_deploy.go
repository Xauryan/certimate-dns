package dnsmcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/certmgmt/deployers"
	"github.com/certimate-go/certimate/internal/domain"
)

// DeploymentFunc transfers issued material to the resolved, published target.
type DeploymentFunc func(ctx context.Context, cfg domain.WorkflowNodeConfigForBizDeploy, accessConfig map[string]any, certificatePEM, privateKeyPEM string) error

var certDeployTools = []toolDefinition{
	{"cert_deploy_query", "List scoped certificate deployment tasks and read the latest deployment result.", []operation{{"list", "cert.deploy.read"}, {"show_log", "cert.deploy.read"}}, []string{"oid", "domain", "aid", "type", "status", "remark", "processid", "limit", "offset"}},
	{"cert_deploy_manage", "Deploy an order to a published Certimate deploy node. Pass config.workflowId and config.nodeId for the destination. Use reset after reconciling a failed or interrupted transfer.", []operation{{"add", "cert.deploy.add"}, {"edit", "cert.deploy.edit"}, {"del", "cert.deploy.delete"}, {"set_active", "cert.deploy.active"}, {"reset", "cert.deploy.reset"}, {"process", "cert.deploy.process"}, {"batch", "cert.deploy.batch"}}, []string{"id", "ids", "aid", "oid", "config", "remark", "active", "act", "reset", "certid", "version"}},
}

var (
	deployConflict = &opError{409, "Deployment state changed or requires reconciliation"}
	deployDBError  = &opError{500, "Could not persist or read certificate deployment"}
)

type deployTask struct {
	Provider    string `db:"provider"`
	ID          string `db:"id"`
	AID         string `db:"access_id"`
	OID         string `db:"order_id"`
	Workflow    string `db:"workflow_id"`
	Node        string `db:"node_id"`
	Remark      string `db:"remark"`
	Active      bool   `db:"active"`
	Status      int    `db:"status"`
	Version     int    `db:"version"`
	Process     string `db:"process_id"`
	Started     int64  `db:"started"`
	Finished    int64  `db:"finished"`
	Created     int64  `db:"created"`
	Automatic   bool   `db:"automatic"`
	RenewalRoot string `db:"renewal_root"`
}

func deployTaskRow(app core.App, field string, id string) (deployTask, *opError) {
	var t deployTask
	err := app.DB().Select("*").From("dns_cert_deploy").Where(dbx.HashExp{field: id}).One(&t)
	if errors.Is(err, sql.ErrNoRows) || id == "" {
		return t, missing
	}
	if err != nil {
		return t, deployDBError
	}
	return t, nil
}

// A credential never supplies destination options directly. A published top-level
// deployment node binds the host, files, resource selectors and reload behavior.
func deployDestination(app core.App, t deployTask) (domain.WorkflowNodeConfigForBizDeploy, *core.Record, *opError) {
	var zero domain.WorkflowNodeConfigForBizDeploy
	w, err := app.FindRecordById(domain.CollectionNameWorkflow, t.Workflow)
	if err != nil || !w.GetBool("hasContent") || !w.GetBool("enabled") {
		return zero, nil, missing
	}
	var g domain.WorkflowGraph
	if w.UnmarshalJSONField("graphContent", &g) != nil {
		return zero, nil, invalid
	}
	cfg, problem := resolveDeployNode(g, t)
	if problem != nil {
		return zero, nil, problem
	}
	a, err := app.FindRecordById(domain.CollectionNameAccess, t.AID)
	if err != nil || !a.GetDateTime("deleted").IsZero() {
		return zero, nil, missing
	}
	p := a.GetString("provider")
	if !deployProviderSupported(p, cfg.Provider) {
		return zero, nil, unsupported
	}
	return cfg, a, nil
}

func resolveDeployNode(g domain.WorkflowGraph, t deployTask) (domain.WorkflowNodeConfigForBizDeploy, *opError) {
	var zero domain.WorkflowNodeConfigForBizDeploy
	var node *domain.WorkflowNode
	for _, n := range g.Nodes {
		if n == nil {
			return zero, invalid
		}
		if n.Id == t.Node {
			if node != nil {
				return zero, invalid
			}
			node = n
		}
	}
	if node == nil || node.Type != domain.WorkflowNodeTypeBizDeploy || node.Data.Disabled {
		return zero, missing
	}
	cfg := node.Data.Config.AsBizDeploy()
	if t.AID == "" || cfg.ProviderAccessId != t.AID {
		return zero, missing
	}
	return cfg, nil
}

func deployProviderSupported(accountProvider, nodeProvider string) bool {
	if nodeProvider != accountProvider && !strings.HasPrefix(nodeProvider, accountProvider+"-") {
		return false
	}
	if _, err := deployers.Registries.Get(domain.DeploymentProviderType(nodeProvider)); err != nil {
		return false
	}
	for _, spec := range deploymentAccountSpecs {
		if spec.matchesNative(accountProvider) {
			return true
		}
	}
	return false
}

func deployInputs(args object, t *deployTask) *opError {
	for name, ptr := range map[string]*string{"aid": &t.AID, "oid": &t.OID, "remark": &t.Remark} {
		if v, supplied := args[name]; supplied {
			s, ok := v.(string)
			if !ok || len(s) > 256 || strings.ContainsAny(s, "\x00\n\r") {
				return invalid
			}
			*ptr = s
		}
	}
	if v, supplied := args["config"]; supplied {
		cfg, ok := v.(map[string]any)
		if !ok || len(cfg) == 0 {
			return invalid
		}
		for name, raw := range cfg {
			id, ok := raw.(string)
			if !ok || id == "" || len(id) > 100 {
				return invalid
			}
			switch name {
			case "workflowId":
				t.Workflow = id
			case "nodeId":
				t.Node = id
			default:
				return invalid
			}
		}
	}
	if t.Workflow == "" || t.Node == "" || t.OID == "" || t.AID == "" {
		return invalid
	}
	return nil
}

func deployAccess(e *core.RequestEvent, g scope, t deployTask, write bool) (certOrder, *opError) {
	if !e.HasSuperuserAuth() || !g.Global || !slices.Contains(g.Accounts, t.AID) {
		return certOrder{}, missing
	}
	o, problem := certOrderRow(e.App, t.OID)
	if problem != nil || !certOrderAllowed(e, g, o, write) {
		return certOrder{}, missing
	}
	a, err := e.App.FindRecordById(domain.CollectionNameAccess, t.AID)
	if err != nil || !a.GetDateTime("deleted").IsZero() {
		return certOrder{}, missing
	}
	return o, nil
}

type deployAccessCheck func(core.App, deployTask, bool) (certOrder, *opError)

func scopedDeployAccess(e *core.RequestEvent, g scope) deployAccessCheck {
	return func(app core.App, t deployTask, write bool) (certOrder, *opError) {
		ev := &core.RequestEvent{App: app, Auth: e.Auth}
		ev.Request = e.Request
		return deployAccess(ev, g, t, write)
	}
}

func deployResultMessage(t deployTask) string {
	switch {
	case t.Started == 0:
		return ""
	case t.Finished == 0:
		return "Deployment started"
	case t.Status == 1:
		return "Deployment started\nDeployment completed"
	default:
		return "Deployment started\nProvider did not confirm completion; reconcile target before resetting"
	}
}

func (s service) certDeploy(e *core.RequestEvent, tool, action string, args object, g scope) (object, *opError) {
	if !e.HasSuperuserAuth() || !g.Global {
		return nil, denied
	}
	if tool == "cert_deploy_query" {
		if action == "list" {
			return deployList(e, args, g)
		}
		if action != "show_log" {
			return nil, invalid
		}
		t, prob := deployTaskRow(e.App, "process_id", str(args, "processid"))
		if prob != nil {
			return nil, prob
		}
		if _, prob = deployAccess(e, g, t, false); prob != nil {
			return nil, prob
		}
		return object{"code": 0, "data": deployResultMessage(t), "time": max(t.Started, t.Finished)}, nil
	}
	if tool != "cert_deploy_manage" {
		return nil, invalid
	}
	if action == "process" {
		return s.deployProcess(e.Request.Context(), e.App, args, scopedDeployAccess(e, g), func(app core.App) bool { return activeGrantIn(e, app) }, slices.Contains(g.Actions, "cert.deploy.reset"), "interface")
	}
	if action == "batch" {
		return deployBatch(e, args, g)
	}
	var result object
	var problem *opError
	err := e.App.RunInTransaction(func(tx core.App) error {
		result, problem = deployChange(tx, action, args, scopedDeployAccess(e, g), nil)
		if problem != nil {
			return errors.New("deployment change declined")
		}
		return nil
	})
	if problem == nil && err != nil {
		problem = deployDBError
	}
	return result, problem
}

func deployList(e *core.RequestEvent, args object, g scope) (object, *opError) {
	offset, limit, ok := paging(args)
	if !ok {
		return nil, invalid
	}
	var tasks []deployTask
	accounts, err := json.Marshal(g.Accounts)
	if err != nil {
		return nil, invalid
	}
	err = e.App.DB().NewQuery(`SELECT t.*,COALESCE(m.legacy_type,a.provider) AS provider FROM dns_cert_deploy t
	JOIN access a ON a.id=t.access_id AND a.deleted=''
	LEFT JOIN dns_cert_account_meta m ON m.access_id=a.id AND m.deploy=1
	WHERE t.access_id IN (SELECT value FROM json_each({:accounts})) ORDER BY t.created DESC,t.id`).Bind(dbx.Params{"accounts": string(accounts)}).All(&tasks)
	if err != nil {
		return nil, deployDBError
	}
	rows := []object{}
	total := 0
	for _, t := range tasks {
		if want := str(args, "oid"); want != "" && want != t.OID {
			continue
		}
		if want := str(args, "aid"); want != "" && want != t.AID {
			continue
		}
		if want := str(args, "type"); want != "" && want != t.Provider {
			continue
		}
		if want := str(args, "remark"); want != "" && want != t.Remark {
			continue
		}
		if want := str(args, "status"); want != "" && want != strconv.Itoa(t.Status) {
			continue
		}
		o, prob := deployAccess(e, g, t, false)
		if prob != nil {
			if prob == missing {
				continue
			}
			return nil, prob
		}
		if want := str(args, "domain"); want != "" && !strings.Contains(strings.ToLower(o.Domain), strings.ToLower(want)) {
			continue
		}
		if total >= offset && len(rows) < limit {
			rows = append(rows, object{"id": t.ID, "aid": t.AID, "oid": t.OID, "domain": o.Domain, "type": t.Provider, "config": object{"workflowId": t.Workflow, "nodeId": t.Node}, "active": t.Active, "remark": t.Remark, "status": t.Status, "version": t.Version, "processid": t.Process, "addtime": t.Created, "lasttime": t.Finished})
		}
		total++
	}
	return object{"rows": rows, "total": total}, nil
}

func deployBool(args object, name string, def bool) (bool, bool) {
	v, exists := args[name]
	if !exists {
		return def, true
	}
	if b, ok := v.(bool); ok {
		return b, true
	}
	switch str(args, name) {
	case "0", "false":
		return false, true
	case "1", "true":
		return true, true
	}
	return false, false
}

func deployCAS(app core.App, t deployTask, values dbx.Params, remove bool) *opError {
	cond := dbx.HashExp{"id": t.ID, "version": t.Version}
	var result sql.Result
	var err error
	if remove {
		result, err = app.DB().Delete("dns_cert_deploy", cond).Execute()
	} else {
		values["version"] = t.Version + 1
		result, err = app.DB().Update("dns_cert_deploy", values, cond).Execute()
	}
	if err != nil {
		return deployDBError
	}
	n, err := result.RowsAffected()
	if err != nil {
		return deployDBError
	}
	if n != 1 {
		return deployConflict
	}
	return nil
}

// Failed transfers and expired claims need an explicit reset. The operator can
// inspect the destination before allowing another delivery after an ambiguous result.
func deployChange(app core.App, action string, args object, check deployAccessCheck, policy *deploymentPolicy) (object, *opError) {
	var t deployTask
	var prob *opError
	if action != "add" {
		t, prob = deployTaskRow(app, "id", str(args, "id"))
		if prob != nil {
			return nil, prob
		}
		if policy == nil {
			if _, prob = check(app, t, true); prob != nil {
				return nil, prob
			}
		}
		if !deployVersionMatches(args, t) || (t.Started > 0 && t.Finished == 0 && (action != "reset" || time.Now().Unix()-t.Started < 3600)) {
			return nil, deployConflict
		}
	}
	previous := t
	values := dbx.Params{}
	switch action {
	case "add", "edit":
		if prob = deployInputs(args, &t); prob != nil {
			return nil, prob
		}
		if _, prob = check(app, t, true); prob != nil {
			return nil, prob
		}
		if _, _, prob = deployDestination(app, t); prob != nil {
			return nil, prob
		}
		if policy != nil && action == "edit" && previous.OID != t.OID && !policy.rebind {
			return nil, invalid
		}
		if policy != nil && action == "edit" &&
			(previous.OID != t.OID || previous.AID != t.AID || previous.Workflow != t.Workflow || previous.Node != t.Node) &&
			previous.Started > 0 && previous.Status != 1 {
			return nil, deployConflict
		}
		values = dbx.Params{"access_id": t.AID, "order_id": t.OID, "workflow_id": t.Workflow, "node_id": t.Node, "remark": t.Remark}
		if policy == nil || previous.OID != t.OID || previous.AID != t.AID || previous.Workflow != t.Workflow || previous.Node != t.Node {
			clearDeploymentState(values)
		}
		if policy != nil {
			if problem := policy.apply(app, t, values); problem != nil {
				return nil, problem
			}
		}
	case "reset":
		clearDeploymentState(values)
		if t.Process != "" && t.Finished == 0 {
			if _, err := app.DB().Update("dns_cert_deploy_attempts", dbx.Params{"outcome": "needs_reconciliation", "finished": time.Now().Unix()},
				dbx.HashExp{"id": t.Process, "outcome": "claimed"}).Execute(); err != nil {
				return nil, deployDBError
			}
		}
		if policy != nil {
			disableDeploymentAutomation(values)
		}
	case "set_active":
		active, ok := deployBool(args, "active", false)
		if _, exists := args["active"]; !ok || !exists {
			return nil, invalid
		}
		values["active"] = active
	case "del":
	default:
		return nil, invalid
	}
	// Interface keys cannot arm a scheduled side effect through a task mutation.
	if policy == nil && action != "del" {
		disableDeploymentAutomation(values)
	}
	if action == "add" {
		t.ID = core.GenerateDefaultRandomId()
		values["id"] = t.ID
		values["created"] = time.Now().Unix()
		if policy != nil {
			values["active"] = false
		}
		if _, err := app.DB().Insert("dns_cert_deploy", values).Execute(); err != nil {
			return nil, deployDBError
		}
	} else if prob = deployCAS(app, t, values, action == "del"); prob != nil {
		return nil, prob
	}
	return object{"code": 0, "id": t.ID, "version": t.Version + 1}, nil
}

func deployVersionMatches(args object, t deployTask) bool {
	v, ok := number(args, "version", t.Version, 1, 1<<30)
	return ok && v == t.Version
}

func deployBatch(e *core.RequestEvent, args object, g scope) (object, *opError) {
	ids, ok := args["ids"].([]any)
	if !ok || len(ids) == 0 || len(ids) > 100 {
		return nil, invalid
	}
	act := str(args, "act")
	mapped := map[string]string{"delete": "del", "reset": "reset", "open": "set_active", "close": "set_active", "cert": "edit"}[act]
	perm := map[string]string{"del": "cert.deploy.delete", "reset": "cert.deploy.reset", "set_active": "cert.deploy.active", "edit": "cert.deploy.edit"}[mapped]
	if mapped == "" {
		return nil, invalid
	}
	if !slices.Contains(g.Actions, perm) {
		return nil, denied
	}
	seen := map[string]bool{}
	var prob *opError
	err := e.App.RunInTransaction(func(tx core.App) error {
		event := &core.RequestEvent{App: tx, Auth: e.Auth}
		event.Request = e.Request
		for _, v := range ids {
			id, ok := v.(string)
			if !ok || id == "" || seen[id] {
				prob = invalid
				return errors.New("invalid batch")
			}
			seen[id] = true
			in := object{"id": id}
			switch act {
			case "open", "close":
				in["active"] = act == "open"
			case "cert":
				in["oid"] = str(args, "certid")
			}
			if _, prob = deployChange(tx, mapped, in, scopedDeployAccess(event, g), nil); prob != nil {
				return errors.New("deployment batch aborted")
			}
		}
		return nil
	})
	if prob != nil {
		return nil, prob
	}
	if err != nil {
		return nil, deployDBError
	}
	return object{"code": 0, "updated": len(ids)}, nil
}

// Resolve account, order, material and target in the same database transaction
// that claims the task. Provider I/O starts only after the claim is durable.
type deployAttempt struct {
	task        deployTask
	cfg         domain.WorkflowNodeConfigForBizDeploy
	access      map[string]any
	certificate *core.Record
}

func claimDeploy(app core.App, args object, check deployAccessCheck, mayReset bool, processID, trigger string) (deployAttempt, *opError) {
	var out deployAttempt
	t, problem := deployTaskRow(app, "id", str(args, "id"))
	if problem != nil {
		return out, problem
	}
	o, problem := check(app, t, true)
	if problem != nil {
		return out, problem
	}
	reset, ok := deployBool(args, "reset", false)
	if !ok {
		return out, invalid
	}
	if reset && !mayReset {
		return out, denied
	}
	if !t.Active || !deployVersionMatches(args, t) ||
		t.Started > 0 && (t.Finished == 0 || !reset || trigger == "admin" && t.Status != 1) {
		return out, deployConflict
	}
	cfg, access, certificate, problem := deploymentMaterial(app, t, o)
	if problem != nil {
		return out, problem
	}
	if _, problem = check(app, t, false); problem != nil {
		return out, problem
	}
	now := time.Now().Unix()
	if problem = deployCAS(app, t, dbx.Params{"process_id": processID, "started": now, "finished": 0, "status": 0}, false); problem != nil {
		return out, problem
	}
	_, err := app.DB().Insert("dns_cert_deploy_attempts", dbx.Params{
		"id": processID, "task_id": t.ID, "order_id": o.ID, "certificate_id": certificate.Id,
		"domain": o.Domain, "access_id": t.AID, "workflow_id": t.Workflow, "node_id": t.Node,
		"provider": cfg.Provider, "trigger": trigger, "started": now, "outcome": "claimed",
	}).Execute()
	if err != nil {
		return out, deployDBError
	}
	t.Version++
	t.Started, t.Process = now, processID
	return deployAttempt{task: t, cfg: cfg, access: access, certificate: certificate}, nil
}

func deploymentMaterial(app core.App, task deployTask, order certOrder) (domain.WorkflowNodeConfigForBizDeploy, map[string]any, *core.Record, *opError) {
	cfg, access, problem := deployDestination(app, task)
	if problem != nil {
		return cfg, nil, nil, problem
	}
	cert, problem := issuedCertMaterial(app, order)
	if problem != nil {
		return cfg, nil, nil, problem
	}
	now := time.Now()
	if !cert.GetDateTime("validityNotAfter").Time().After(now) || cert.GetDateTime("validityNotBefore").Time().After(now) {
		return cfg, nil, nil, deployConflict
	}
	var secretConfig map[string]any
	if err := access.UnmarshalJSONField("config", &secretConfig); err != nil {
		return cfg, nil, nil, invalid
	}
	return cfg, secretConfig, cert, nil
}

func finishDeploy(app core.App, task deployTask, status int, outcome string) *opError {
	var problem *opError
	err := app.RunInTransaction(func(tx core.App) error {
		now := time.Now().Unix()
		if problem = deployCAS(tx, task, dbx.Params{"status": status, "finished": now}, false); problem != nil {
			return errors.New("deployment claim changed")
		}
		result, err := tx.DB().Update("dns_cert_deploy_attempts", dbx.Params{"outcome": outcome, "finished": now},
			dbx.HashExp{"id": task.Process, "outcome": "claimed"}).Execute()
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err == nil && n != 1 {
			return errors.New("deployment history changed")
		}
		return err
	})
	if problem == nil && err != nil {
		problem = deployDBError
	}
	return problem
}

func (s service) deployProcess(parent context.Context, app core.App, args object, check deployAccessCheck, live func(core.App) bool, mayReset bool, trigger string) (object, *opError) {
	if s.deploy == nil {
		return nil, unsupported
	}
	processID := core.GenerateDefaultRandomId()
	var a deployAttempt
	var problem *opError
	err := app.RunInTransaction(func(tx core.App) error {
		if !live(tx) {
			problem = denied
			return errors.New("deployment authorization expired")
		}
		a, problem = claimDeploy(tx, args, check, mayReset, processID, trigger)
		if problem != nil {
			return errors.New("deployment claim declined")
		}
		return nil
	})
	if problem != nil {
		return nil, problem
	}
	if err != nil {
		return nil, deployDBError
	}
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	// Revalidate the exact published target, active account and certificate before
	// sending either part of the key pair. An edit racing the durable claim aborts.
	o, problem := check(app, a.task, true)
	if problem == nil {
		cfg, access, cert, currentProblem := deploymentMaterial(app, a.task, o)
		if !live(app) || ctx.Err() != nil || currentProblem != nil || !reflect.DeepEqual(cfg, a.cfg) ||
			!reflect.DeepEqual(access, a.access) || cert.Id != a.certificate.Id ||
			cert.GetString("certificate") != a.certificate.GetString("certificate") ||
			cert.GetString("privateKey") != a.certificate.GetString("privateKey") {
			problem = deployConflict
		}
	}
	if problem != nil {
		if saveProblem := finishDeploy(app, a.task, -1, "blocked"); saveProblem != nil {
			return nil, saveProblem
		}
		return nil, problem
	}
	err = s.deploy(ctx, a.cfg, a.access, a.certificate.GetString("certificate"), a.certificate.GetString("privateKey"))
	status, outcome := 1, "completed"
	if err != nil {
		status, outcome = -1, "needs_reconciliation"
	}
	if problem = finishDeploy(app, a.task, status, outcome); problem != nil {
		return nil, problem
	}
	if err != nil {
		return nil, &opError{502, "Deployment not confirmed; reconcile the destination before resetting"}
	}
	return object{"code": 0, "id": a.task.ID, "processid": processID, "version": a.task.Version + 1}, nil
}
