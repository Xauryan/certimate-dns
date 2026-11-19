package dnsmcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

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
	Provider string `db:"provider"`
	ID       string `db:"id"`
	AID      string `db:"access_id"`
	OID      string `db:"order_id"`
	Workflow string `db:"workflow_id"`
	Node     string `db:"node_id"`
	Remark   string `db:"remark"`
	Active   bool   `db:"active"`
	Status   int    `db:"status"`
	Version  int    `db:"version"`
	Process  string `db:"process_id"`
	Started  int64  `db:"started"`
	Finished int64  `db:"finished"`
	Created  int64  `db:"created"`
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
	var node *domain.WorkflowNode
	for _, n := range g.Nodes {
		if n == nil {
			return zero, nil, invalid
		}
		if n.Id == t.Node {
			if node != nil {
				return zero, nil, invalid
			}
			node = n
		}
	}
	if node == nil || node.Type != domain.WorkflowNodeTypeBizDeploy || node.Data.Disabled {
		return zero, nil, missing
	}
	cfg := node.Data.Config.AsBizDeploy()
	if t.AID == "" || cfg.ProviderAccessId != t.AID {
		return zero, nil, missing
	}
	a, err := app.FindRecordById(domain.CollectionNameAccess, t.AID)
	if err != nil || !a.GetDateTime("deleted").IsZero() {
		return zero, nil, missing
	}
	p := a.GetString("provider")
	supported := false
	for _, spec := range deploymentAccountSpecs {
		if spec.matchesNative(p) {
			supported = true
			break
		}
	}
	if !supported || (cfg.Provider != p && !strings.HasPrefix(cfg.Provider, p+"-")) {
		return zero, nil, unsupported
	}
	return cfg, a, nil
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
		msg := "Deployment started"
		if t.Finished != 0 {
			if t.Status == 1 {
				msg += "\nDeployment completed"
			} else {
				msg += "\nProvider did not confirm completion; reconcile target before resetting"
			}
		}
		return object{"code": 0, "data": msg, "time": max(t.Started, t.Finished)}, nil
	}
	if tool != "cert_deploy_manage" {
		return nil, invalid
	}
	if action == "process" {
		return s.deployProcess(e, args, g)
	}
	if action == "batch" {
		return deployBatch(e, args, g)
	}
	return deployChange(e, action, args, g)
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
func deployChange(e *core.RequestEvent, action string, args object, g scope) (object, *opError) {
	var t deployTask
	var prob *opError
	if action != "add" {
		t, prob = deployTaskRow(e.App, "id", str(args, "id"))
		if prob != nil {
			return nil, prob
		}
		if _, prob = deployAccess(e, g, t, true); prob != nil {
			return nil, prob
		}
		if !deployVersionMatches(args, t) || (t.Started > 0 && t.Finished == 0 && (action != "reset" || time.Now().Unix()-t.Started < 3600)) {
			return nil, deployConflict
		}
	}
	values := dbx.Params{}
	switch action {
	case "add", "edit":
		if prob = deployInputs(args, &t); prob != nil {
			return nil, prob
		}
		if _, prob = deployAccess(e, g, t, true); prob != nil {
			return nil, prob
		}
		if _, _, prob = deployDestination(e.App, t); prob != nil {
			return nil, prob
		}
		values = dbx.Params{"access_id": t.AID, "order_id": t.OID, "workflow_id": t.Workflow, "node_id": t.Node, "remark": t.Remark, "status": 0, "process_id": "", "started": 0, "finished": 0}
	case "reset":
		values = dbx.Params{"status": 0, "process_id": "", "started": 0, "finished": 0}
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
	if action == "add" {
		t.ID = core.GenerateDefaultRandomId()
		values["id"] = t.ID
		values["created"] = time.Now().Unix()
		if _, err := e.App.DB().Insert("dns_cert_deploy", values).Execute(); err != nil {
			return nil, deployDBError
		}
	} else if prob = deployCAS(e.App, t, values, action == "del"); prob != nil {
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
			if _, prob = deployChange(event, mapped, in, g); prob != nil {
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

func claimDeploy(e *core.RequestEvent, args object, g scope, processID string) (deployAttempt, *opError) {
	var out deployAttempt
	t, prob := deployTaskRow(e.App, "id", str(args, "id"))
	if prob != nil {
		return out, prob
	}
	o, prob := deployAccess(e, g, t, true)
	if prob != nil {
		return out, prob
	}
	reset, ok := deployBool(args, "reset", false)
	if !ok {
		return out, invalid
	}
	if reset && !slices.Contains(g.Actions, "cert.deploy.reset") {
		return out, denied
	}
	if !t.Active || !deployVersionMatches(args, t) || t.Started > 0 && (t.Finished == 0 || !reset) {
		return out, deployConflict
	}
	cfg, access, prob := deployDestination(e.App, t)
	if prob != nil {
		return out, prob
	}
	cert, prob := certReadMaterial(e, g, o)
	if prob != nil {
		return out, prob
	}
	now := time.Now()
	if !cert.GetDateTime("validityNotAfter").Time().After(now) || cert.GetDateTime("validityNotBefore").Time().After(now) {
		return out, deployConflict
	}
	if err := access.UnmarshalJSONField("config", &out.access); err != nil {
		return out, invalid
	}
	if prob = deployCAS(e.App, t, dbx.Params{"process_id": processID, "started": now.Unix(), "finished": 0, "status": 0}, false); prob != nil {
		return out, prob
	}
	t.Version++
	out.task = t
	out.cfg = cfg
	out.certificate = cert
	return out, nil
}

func (s service) deployProcess(e *core.RequestEvent, args object, g scope) (object, *opError) {
	if s.deploy == nil {
		return nil, unsupported
	}
	processID := core.GenerateDefaultRandomId()
	var a deployAttempt
	var problem *opError
	err := e.App.RunInTransaction(func(tx core.App) error {
		ev := &core.RequestEvent{App: tx, Auth: e.Auth}
		ev.Request = e.Request
		a, problem = claimDeploy(ev, args, g, processID)
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
	ctx, cancel := context.WithTimeout(e.Request.Context(), 90*time.Second)
	defer cancel()
	// Issuance, account disablement or key revocation can race the claim.
	// Check the live credential/zone immediately before transferring material.
	if _, prob := deployAccess(e, g, a.task, true); prob != nil || !activeGrant(e) {
		if problem = deployCAS(e.App, a.task, dbx.Params{"status": -1, "finished": time.Now().Unix()}, false); problem != nil {
			return nil, problem
		}
		return nil, denied
	}
	err = s.deploy(ctx, a.cfg, a.access, a.certificate.GetString("certificate"), a.certificate.GetString("privateKey"))
	status := 1
	if err != nil {
		status = -1
	}
	if problem = deployCAS(e.App, a.task, dbx.Params{"status": status, "finished": time.Now().Unix()}, false); problem != nil {
		return nil, problem
	}
	if err != nil {
		return nil, &opError{502, "Deployment not confirmed; reconcile the destination before resetting"}
	}
	return object{"code": 0, "id": a.task.ID, "processid": processID, "version": a.task.Version + 1}, nil
}
