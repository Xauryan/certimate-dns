package dnsmcp

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"

	"github.com/certimate-go/certimate/internal/domain"
)

// BindCertificateDeployments registers the deployment console with its superuser routes.
func BindCertificateDeployments(admin *router.RouterGroup[*core.RequestEvent], deploy DeploymentFunc) {
	g := admin.Group("/dnscert/deployments").Bind(apis.BodyLimit(16 << 10))
	g.GET("", listAdminDeployments)
	g.GET("/orders", deploymentOrderChoices)
	g.GET("/targets", deploymentTargetChoices)
	g.GET("/{id}", adminDeploymentDetail)
	g.GET("/{id}/logs", adminDeploymentLogs)
	g.POST("/batch", adminDeploymentBatch)

	s := service{deploy: deploy}
	g.POST("", s.adminDeploymentChange("add"))
	g.PATCH("/{id}", s.adminDeploymentChange("edit"))
	g.DELETE("/{id}", s.adminDeploymentChange("del"))
	g.POST("/{id}/active", s.adminDeploymentChange("set_active"))
	g.POST("/{id}/reset", s.adminDeploymentChange("reset"))
	g.POST("/{id}/process", s.adminDeploymentChange("process"))
}

func liveDeploySession(app core.App, e *core.RequestEvent) bool {
	if !e.HasSuperuserAuth() {
		return false
	}
	token := e.Request.Header.Get("Authorization")
	if len(token) > 7 && strings.EqualFold(token[:7], "Bearer ") {
		token = token[7:]
	}
	if token == "" {
		return false
	}
	record, err := app.FindAuthRecordByToken(token, core.TokenTypeAuth)
	return err == nil && record.IsSuperuser() && record.Id == e.Auth.Id
}

type adminDeploymentInput struct {
	OrderID       string `json:"orderId"`
	AccessID      string `json:"accessId"`
	WorkflowID    string `json:"workflowId"`
	NodeID        string `json:"nodeId"`
	Remark        string `json:"remark"`
	Version       int    `json:"version"`
	Confirmed     bool   `json:"confirmed"`
	Active        *bool  `json:"active"`
	RunAgain      bool   `json:"runAgain"`
	Automatic     bool   `json:"automatic"`
	FollowRenewal bool   `json:"followRenewal"`
	Rebind        bool   `json:"rebind"`
}

func decodeAdminDeployment(e *core.RequestEvent, in any) bool {
	dec := json.NewDecoder(e.Request.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(in) == nil && dec.Decode(new(any)) == io.EOF
}

func nativeDeploymentOrder(app core.App, task deployTask, _ bool) (certOrder, *opError) {
	return certOrderRow(app, task.OID)
}

func nativeDeploymentCheck(action string) deployAccessCheck {
	// Recovery actions remain available after the linked order is removed.
	if action == "add" || action == "edit" {
		return nativeDeploymentOrder
	}
	return func(core.App, deployTask, bool) (certOrder, *opError) { return certOrder{}, nil }
}

func adminDeployTransaction(e *core.RequestEvent, fn func(core.App) *opError) *opError {
	var problem *opError
	err := e.App.RunInTransaction(func(tx core.App) error {
		if !liveDeploySession(tx, e) {
			problem = denied
		} else {
			problem = fn(tx)
		}
		if problem != nil {
			return errors.New("deployment change declined")
		}
		return nil
	})
	if problem == nil && err != nil {
		return deployDBError
	}
	return problem
}

func (s service) adminDeploymentChange(action string) func(*core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		if !validOrigin(e) || !liveDeploySession(e.App, e) {
			return adminDeployReply(e, nil, denied)
		}
		var in adminDeploymentInput
		if !decodeAdminDeployment(e, &in) || !in.Confirmed || action != "add" && !validDeploymentVersion(in.Version) {
			return adminDeployReply(e, nil, invalid)
		}
		args := object{"id": e.Request.PathValue("id"), "version": strconv.Itoa(in.Version)}
		switch action {
		case "add", "edit":
			args["oid"], args["aid"], args["remark"] = in.OrderID, in.AccessID, in.Remark
			args["config"] = object{"workflowId": in.WorkflowID, "nodeId": in.NodeID}
		case "set_active":
			if in.Active == nil {
				return adminDeployReply(e, nil, invalid)
			}
			args["active"] = *in.Active
		case "process":
			args["reset"] = in.RunAgain
			result, problem := s.deployProcess(e.Request.Context(), e.App, args, nativeDeploymentOrder, func(app core.App) bool {
				return liveDeploySession(app, e)
			}, true, "admin")
			return adminDeployReply(e, result, problem)
		}
		var result object
		problem := adminDeployTransaction(e, func(tx core.App) *opError {
			var problem *opError
			result, problem = deployChange(tx, action, args, nativeDeploymentCheck(action),
				&deploymentPolicy{automatic: in.Automatic, followRenewals: in.FollowRenewal, rebind: in.Rebind})
			return problem
		})
		return adminDeployReply(e, result, problem)
	}
}

func validDeploymentVersion(version int) bool {
	return version > 0 && version <= 1<<30
}

func adminDeploymentBatch(e *core.RequestEvent) error {
	if !validOrigin(e) || !liveDeploySession(e.App, e) {
		return adminDeployReply(e, nil, denied)
	}
	var in struct {
		Action    string `json:"action"`
		Confirmed bool   `json:"confirmed"`
		OrderID   string `json:"orderId"`
		Tasks     []struct {
			ID      string `json:"id"`
			Version int    `json:"version"`
		} `json:"tasks"`
	}
	if !decodeAdminDeployment(e, &in) || !in.Confirmed || len(in.Tasks) == 0 || len(in.Tasks) > 100 {
		return adminDeployReply(e, nil, invalid)
	}
	action := map[string]string{"delete": "del", "reset": "reset", "enable": "set_active", "pause": "set_active", "rebind": "edit"}[in.Action]
	if action == "" {
		return adminDeployReply(e, nil, invalid)
	}
	seen := map[string]bool{}
	for _, task := range in.Tasks {
		if task.ID == "" || seen[task.ID] || !validDeploymentVersion(task.Version) {
			return adminDeployReply(e, nil, invalid)
		}
		seen[task.ID] = true
	}
	problem := adminDeployTransaction(e, func(tx core.App) *opError {
		for _, task := range in.Tasks {
			args := object{"id": task.ID, "version": strconv.Itoa(task.Version)}
			switch action {
			case "set_active":
				args["active"] = in.Action == "enable"
			case "edit":
				args["oid"] = in.OrderID
			}
			if _, problem := deployChange(tx, action, args, nativeDeploymentCheck(action), &deploymentPolicy{rebind: true}); problem != nil {
				return problem
			}
		}
		return nil
	})
	return adminDeployReply(e, object{"updated": len(in.Tasks)}, problem)
}

func adminDeployReply(e *core.RequestEvent, result any, problem *opError) error {
	e.Response.Header().Set("Cache-Control", "no-store")
	if problem == nil {
		return e.JSON(http.StatusOK, result)
	}
	message := problem.message
	switch problem {
	case missing:
		message = "Certificate order, deployment task or published target unavailable"
	case denied:
		message = "Active administrator session required"
	}
	return e.Error(problem.status, message, nil)
}

type adminDeployRow struct {
	deployTask
	Domain        string `db:"domain"`
	OrderState    string `db:"order_state"`
	AccessName    string `db:"access_name"`
	WorkflowName  string `db:"workflow_name"`
	PolicyCurrent bool   `db:"policy_current"`
}

type deploymentView struct {
	ID            string `json:"id"`
	OrderID       string `json:"orderId"`
	Domain        string `json:"domain"`
	OrderState    string `json:"orderState"`
	AccessID      string `json:"accessId"`
	AccessName    string `json:"accessName"`
	Provider      string `json:"provider"`
	WorkflowID    string `json:"workflowId"`
	WorkflowName  string `json:"workflowName"`
	NodeID        string `json:"nodeId"`
	Remark        string `json:"remark"`
	Active        bool   `json:"active"`
	Status        int    `json:"status"`
	Version       int    `json:"version"`
	ProcessID     string `json:"processId"`
	Started       int64  `json:"started"`
	Finished      int64  `json:"finished"`
	Created       int64  `json:"created"`
	Result        string `json:"result,omitempty"`
	Automatic     bool   `json:"automatic"`
	FollowRenewal bool   `json:"followRenewal"`
	PolicyCurrent bool   `json:"policyCurrent"`
}

func deploymentProjection(r adminDeployRow) deploymentView {
	return deploymentView{
		ID: r.ID, OrderID: r.OID, Domain: r.Domain, OrderState: r.OrderState,
		AccessID: r.AID, AccessName: r.AccessName, Provider: r.Provider,
		WorkflowID: r.Workflow, WorkflowName: r.WorkflowName, NodeID: r.Node, Remark: r.Remark,
		Active: r.Active, Status: r.Status, Version: r.Version, ProcessID: r.Process,
		Started: r.Started, Finished: r.Finished, Created: r.Created,
		Automatic: r.Automatic, FollowRenewal: r.RenewalRoot != "", PolicyCurrent: r.PolicyCurrent,
	}
}

const adminDeploymentFrom = ` FROM dns_cert_deploy t
	LEFT JOIN dns_cert_orders o ON o.id=t.order_id
	LEFT JOIN access a ON a.id=t.access_id
	LEFT JOIN workflow w ON w.id=t.workflow_id
	LEFT JOIN dns_cert_renewals r ON r.root_id=t.renewal_root AND r.enabled=1`
const adminDeploymentSelect = `SELECT t.*,COALESCE(o.domain,'') AS domain,COALESCE(o.state,'') AS order_state,
	COALESCE(a.name,'') AS access_name,COALESCE(a.provider,'') AS provider,COALESCE(w.name,'') AS workflow_name,
	COALESCE(t.automatic_approved=1 AND w.enabled=1 AND w.hasContent=1
		AND a.deleted='' AND (t.renewal_root='' OR r.root_id IS NOT NULL),0) AS policy_current` + adminDeploymentFrom
const adminDeploymentPageSize = 20

func adminDeploymentPage(e *core.RequestEvent) (int, bool) {
	q := e.Request.URL.Query()
	if !q.Has("page") {
		return 1, true
	}
	return number(object{"page": q.Get("page")}, "page", 1, 1, 1000000)
}

func listAdminDeployments(e *core.RequestEvent) error {
	q := e.Request.URL.Query()
	page, ok := adminDeploymentPage(e)
	keyword := strings.TrimSpace(q.Get("q"))
	state, order, access := q.Get("status"), q.Get("orderId"), q.Get("accessId")
	domain, remark, provider := strings.TrimSpace(q.Get("domain")), strings.TrimSpace(q.Get("remark")), q.Get("provider")
	if !ok || max(len(keyword), len(order), len(access), len(domain), len(remark), len(provider)) > 256 ||
		state != "" && state != "-1" && state != "0" && state != "1" {
		return adminDeployReply(e, nil, invalid)
	}
	const where = ` WHERE ({:order}='' OR t.order_id={:order}) AND ({:access}='' OR t.access_id={:access})
		AND ({:status}='' OR CAST(t.status AS TEXT)={:status}) AND ({:provider}='' OR a.provider={:provider})
		AND ({:domain}='' OR instr(lower(o.domain),lower({:domain}))>0) AND ({:remark}='' OR instr(lower(t.remark),lower({:remark}))>0)
		AND ({:keyword}='' OR instr(lower(COALESCE(o.domain,'') || ' ' || t.remark || ' ' || COALESCE(a.name,'') ||
			' ' || COALESCE(w.name,'')),lower({:keyword}))>0)`
	params := dbx.Params{"order": order, "access": access, "status": state, "keyword": keyword, "domain": domain,
		"remark": remark, "provider": provider, "limit": adminDeploymentPageSize, "offset": (page - 1) * adminDeploymentPageSize}
	ctx := e.Request.Context()
	var total int
	if err := e.App.DB().NewQuery("SELECT count(*)" + adminDeploymentFrom + where).Bind(params).WithContext(ctx).Row(&total); err != nil {
		return adminDeployReply(e, nil, deployDBError)
	}
	var rows []adminDeployRow
	if err := e.App.DB().NewQuery(adminDeploymentSelect + where + " ORDER BY t.created DESC,t.id LIMIT {:limit} OFFSET {:offset}").
		Bind(params).WithContext(ctx).All(&rows); err != nil {
		return adminDeployReply(e, nil, deployDBError)
	}
	items := make([]deploymentView, 0, len(rows))
	for _, row := range rows {
		items = append(items, deploymentProjection(row))
	}
	return adminDeployReply(e, object{"items": items, "total": total}, nil)
}

func adminDeploymentDetail(e *core.RequestEvent) error {
	var row adminDeployRow
	err := e.App.DB().NewQuery(adminDeploymentSelect + " WHERE t.id={:id}").
		Bind(dbx.Params{"id": e.Request.PathValue("id")}).WithContext(e.Request.Context()).One(&row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminDeployReply(e, nil, missing)
		}
		return adminDeployReply(e, nil, deployDBError)
	}
	view := deploymentProjection(row)
	view.Result = deployResultMessage(row.deployTask)
	if row.Process != "" && row.Status == -1 {
		var outcome string
		err := e.App.DB().Select("outcome").From("dns_cert_deploy_attempts").
			Where(dbx.HashExp{"id": row.Process}).WithContext(e.Request.Context()).Row(&outcome)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return adminDeployReply(e, nil, deployDBError)
		}
		if outcome == "blocked" {
			view.Result = "Deployment stopped before sending certificate material"
		}
	}
	return adminDeployReply(e, view, nil)
}

type deploymentLog struct {
	ID            string `db:"id" json:"id"`
	OrderID       string `db:"order_id" json:"orderId"`
	CertificateID string `db:"certificate_id" json:"certificateId"`
	Domain        string `db:"domain" json:"domain"`
	AccessID      string `db:"access_id" json:"accessId"`
	WorkflowID    string `db:"workflow_id" json:"workflowId"`
	NodeID        string `db:"node_id" json:"nodeId"`
	Provider      string `db:"provider" json:"provider"`
	Trigger       string `db:"trigger" json:"trigger"`
	Started       int64  `db:"started" json:"started"`
	Finished      int64  `db:"finished" json:"finished"`
	Outcome       string `db:"outcome" json:"outcome"`
}

func adminDeploymentLogs(e *core.RequestEvent) error {
	id := e.Request.PathValue("id")
	page, ok := adminDeploymentPage(e)
	if !ok {
		return adminDeployReply(e, nil, invalid)
	}
	ctx := e.Request.Context()
	params := dbx.Params{"id": id, "limit": adminDeploymentPageSize, "offset": (page - 1) * adminDeploymentPageSize}
	var total int
	const from = " FROM dns_cert_deploy_attempts WHERE task_id={:id}"
	if err := e.App.DB().NewQuery("SELECT count(*)" + from).Bind(params).WithContext(ctx).Row(&total); err != nil {
		return adminDeployReply(e, nil, deployDBError)
	}
	items := []deploymentLog{}
	if err := e.App.DB().NewQuery("SELECT id,order_id,certificate_id,domain,access_id,workflow_id,node_id,provider,trigger,started,finished,outcome" + from +
		" ORDER BY started DESC,rowid DESC LIMIT {:limit} OFFSET {:offset}").Bind(params).WithContext(ctx).All(&items); err != nil {
		return adminDeployReply(e, nil, deployDBError)
	}
	return adminDeployReply(e, object{"items": items, "total": total}, nil)
}

func deploymentOrderChoices(e *core.RequestEvent) error {
	q := e.Request.URL.Query()
	keyword := strings.TrimSpace(q.Get("q"))
	id := q.Get("id")
	if len(keyword) > 256 || len(id) > 256 {
		return adminDeployReply(e, nil, invalid)
	}
	type orderChoice struct {
		ID     string `db:"id" json:"id"`
		Domain string `db:"domain" json:"domain"`
		State  string `db:"state" json:"state"`
	}
	items := []orderChoice{}
	err := e.App.DB().NewQuery(`SELECT id,domain,state FROM dns_cert_orders
		WHERE state<>'deleted' AND ({:id}='' OR id={:id})
		AND ({:keyword}='' OR instr(lower(domain || ' ' || id),lower({:keyword}))>0)
		ORDER BY created DESC,id LIMIT 20`).Bind(dbx.Params{"keyword": keyword, "id": id}).WithContext(e.Request.Context()).All(&items)
	if err != nil {
		return adminDeployReply(e, nil, deployDBError)
	}
	return adminDeployReply(e, object{"items": items}, nil)
}

func deploymentTargetChoices(e *core.RequestEvent) error {
	q := e.Request.URL.Query()
	keyword := strings.TrimSpace(q.Get("q"))
	access, workflow, node := q.Get("accessId"), q.Get("workflowId"), q.Get("nodeId")
	if len(keyword) > 256 || max(len(access), len(workflow), len(node)) > 100 {
		return adminDeployReply(e, nil, invalid)
	}
	type targetChoice struct {
		AccessID     string `json:"accessId"`
		AccessName   string `json:"accessName"`
		Provider     string `json:"provider"`
		WorkflowID   string `json:"workflowId"`
		WorkflowName string `json:"workflowName"`
		NodeID       string `json:"nodeId"`
		NodeName     string `json:"nodeName"`
	}
	// The SQL narrows discovery to top-level, enabled nodes with active accounts.
	// Validate each workflow's published target with the same resolver as writes.
	rows, err := e.App.DB().NewQuery(`WITH candidates AS (
		SELECT w.id AS workflow_id,w.name AS workflow_name,w.graphContent,
			json_extract(w.graphContent,n.fullkey || '.id') AS node_id,
			COALESCE(json_extract(w.graphContent,n.fullkey || '.data.name'),'') AS node_name,
			json_extract(w.graphContent,n.fullkey || '.data.config.providerAccessId') AS access_id
		FROM workflow w JOIN json_each(CASE WHEN json_valid(w.graphContent) THEN w.graphContent ELSE '{}' END,'$.nodes') n
		WHERE w.enabled=1 AND w.hasContent=1 AND n.type='object'
		AND json_extract(w.graphContent,n.fullkey || '.type')='bizDeploy'
		AND COALESCE(json_extract(w.graphContent,n.fullkey || '.data.disabled'),0)=0
		AND json_type(w.graphContent,n.fullkey || '.id')='text'
		AND length(json_extract(w.graphContent,n.fullkey || '.id')) BETWEEN 1 AND 100)
		SELECT c.access_id,a.name,a.provider,c.workflow_id,c.workflow_name,c.node_id,c.node_name,c.graphContent FROM candidates c
		JOIN access a ON a.id=c.access_id AND a.deleted=''
		WHERE ({:access}='' OR c.access_id={:access}) AND ({:workflow}='' OR c.workflow_id={:workflow})
		AND ({:node}='' OR c.node_id={:node})
		AND ({:keyword}='' OR instr(lower(a.name || ' ' || a.provider || ' ' || c.workflow_name || ' ' || c.node_name || ' ' || c.node_id),lower({:keyword}))>0)
		ORDER BY c.workflow_name,c.workflow_id,c.node_id`).Bind(dbx.Params{"keyword": keyword, "access": access, "workflow": workflow, "node": node}).WithContext(e.Request.Context()).Rows()
	if err != nil {
		return adminDeployReply(e, nil, deployDBError)
	}
	defer rows.Close()
	items := []targetChoice{}
	for len(items) < adminDeploymentPageSize && rows.Next() {
		var v targetChoice
		var graphJSON []byte
		if err := rows.Scan(&v.AccessID, &v.AccessName, &v.Provider, &v.WorkflowID, &v.WorkflowName, &v.NodeID, &v.NodeName, &graphJSON); err != nil {
			return adminDeployReply(e, nil, deployDBError)
		}
		var graph domain.WorkflowGraph
		if json.Unmarshal(graphJSON, &graph) != nil {
			continue
		}
		if cfg, problem := resolveDeployNode(graph, deployTask{AID: v.AccessID, Node: v.NodeID}); problem == nil &&
			deployProviderSupported(v.Provider, cfg.Provider) {
			items = append(items, v)
		}
	}
	if err := rows.Err(); err != nil {
		return adminDeployReply(e, nil, deployDBError)
	}
	return adminDeployReply(e, object{"items": items}, nil)
}
