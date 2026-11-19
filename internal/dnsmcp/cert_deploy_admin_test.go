package dnsmcp_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnsmcp"
	"github.com/certimate-go/certimate/internal/domain"
)

const deploymentPath = "/api/dnscert/deployments"
const deploymentDomain = "deployment.example.test"

type deploymentFixture struct {
	*authFixture
	issuer, target, workflow *core.Record
	token, interfaceKey      string
}

func setupDeployment(t *testing.T, deploy dnsmcp.DeploymentFunc) *deploymentFixture {
	t.Helper()
	f := &deploymentFixture{authFixture: setupInterface(t)}
	input := f.keyInput([]string{"cert.deploy.read", "cert.deploy.add"}, []string{"mcp"})
	input["global"] = true
	f.interfaceKey = f.issue(t, session(t, f.admin), input).bearer()
	f.issuer = f.save(t, "access", fields{"name": "Synthetic issuer", "provider": "aliyun", "config": fields{}})
	f.target = f.save(t, "access", fields{"name": "Synthetic deployer", "provider": "aliyun", "config": fields{"accessKeyId": configSentinel}})
	f.workflow = f.save(t, "workflow", fields{
		"name": "Published fixture", "trigger": "manual", "enabled": true, "hasContent": true, "hasDraft": true,
		"graphContent": fields{"nodes": []fields{
			{"id": "start", "type": "start"},
			{"id": "ship", "type": "bizDeploy", "data": fields{"name": "Published target", "config": fields{
				"provider": "aliyun-cdn", "providerAccessId": f.target.Id, "providerConfig": fields{"domain": deploymentDomain},
			}}},
			{"id": "disabled", "type": "bizDeploy", "data": fields{"disabled": true, "config": fields{
				"provider": "aliyun-cdn", "providerAccessId": f.target.Id,
			}}},
			{"id": "unsupported", "type": "bizDeploy", "data": fields{"config": fields{
				"provider": "aliyun-unsupported", "providerAccessId": f.target.Id,
			}}},
			{"id": "end", "type": "end"},
		}},
		"graphDraft": fields{"nodes": []fields{{"id": "draft-target", "type": "bizDeploy", "data": fields{"config": fields{
			"provider": "aliyun-cdn", "providerAccessId": f.target.Id,
		}}}}},
	})
	r, err := apis.NewRouter(f.app)
	if err != nil {
		t.Fatal(err)
	}
	dnsmcp.BindCertificateDeployments(r.Group("/api").Bind(apis.RequireSuperuserAuth()), deploy)
	f.mux, err = r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	w := f.request(http.MethodPost, "/api/collections/_superusers/auth-with-password", "", "application/json",
		testJSON(t, fields{"identity": "admin@example.test", "password": "synthetic-admin-password"}))
	expectStatus(t, w, http.StatusOK)
	var auth struct{ Token string }
	readJSON(t, w, &auth)
	f.token = auth.Token
	return f
}

func (f *deploymentFixture) save(t *testing.T, collection string, data fields) *core.Record {
	t.Helper()
	c, err := f.app.FindCollectionByNameOrId(collection)
	if err != nil {
		t.Fatal(err)
	}
	r := core.NewRecord(c)
	r.Load(data)
	if err = f.app.SaveNoValidate(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *deploymentFixture) order(t *testing.T) string {
	t.Helper()
	now := time.Now().UTC()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), DNSNames: []string{deploymentDomain},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := f.save(t, "certificate", fields{
		"source": "request", "validityNotBefore": leaf.NotBefore, "validityNotAfter": leaf.NotAfter,
		"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		"privateKey":  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: priv})),
	})
	id := core.GenerateDefaultRandomId()
	_, err = f.app.DB().Insert("dns_cert_orders", dbx.Params{
		"id": id, "access_id": f.issuer.Id, "provider": "aliyun", "domain": deploymentDomain, "algorithm": "EC256",
		"request_json": "{}", "state": "issued", "certificate_id": cert.Id, "created": now.Unix(), "updated": now.Unix(),
	}).Execute()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type deploymentState struct {
	ID, OrderID, Result          string
	Active, Automatic            bool
	PolicyCurrent, FollowRenewal bool
	Started, Finished            int64
	Status, Version              int
}

func (f *deploymentFixture) call(t *testing.T, method, path string, data fields, status int) *httptest.ResponseRecorder {
	t.Helper()
	w := f.request(method, deploymentPath+path, f.token, "application/json", testJSON(t, data))
	if w.Code != status {
		t.Fatalf("%s %s returned HTTP %d, want %d", method, path, w.Code, status)
	}
	if strings.Contains(w.Body.String(), configSentinel) || strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Fatal("deployment response disclosed provider material")
	}
	return w
}

func (f *deploymentFixture) state(t *testing.T, id string) deploymentState {
	t.Helper()
	var st deploymentState
	readJSON(t, f.call(t, http.MethodGet, "/"+id, nil, http.StatusOK), &st)
	return st
}

func (f *deploymentFixture) config(order string) fields {
	return fields{"orderId": order, "accessId": f.target.Id, "workflowId": f.workflow.Id, "nodeId": "ship",
		"remark": "Test deployment", "confirmed": true}
}

func (f *deploymentFixture) add(t *testing.T, data fields) string {
	t.Helper()
	var st deploymentState
	readJSON(t, f.call(t, http.MethodPost, "", data, http.StatusOK), &st)
	if st.ID == "" || st.Version != 1 {
		t.Fatal("missing created task ID or version")
	}
	return st.ID
}

func (f *deploymentFixture) active(t *testing.T, id string, active bool) {
	t.Helper()
	st := f.state(t, id)
	f.call(t, http.MethodPost, "/"+id+"/active", fields{"version": st.Version, "confirmed": true, "active": active}, http.StatusOK)
}

type observedDeployment struct {
	OrderID, Trigger, Outcome string
}

func (f *deploymentFixture) logs(t *testing.T, task string) []observedDeployment {
	t.Helper()
	var page struct{ Items []observedDeployment }
	readJSON(t, f.call(t, http.MethodGet, "/"+task+"/logs", nil, http.StatusOK), &page)
	return page.Items
}

func TestNativeCertificateDeploymentSessionAndBatch(t *testing.T) {
	var transfers atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	f := setupDeployment(t, func(ctx context.Context, cfg domain.WorkflowNodeConfigForBizDeploy, access map[string]any, cert, key string) error {
		if cfg.Provider != "aliyun-cdn" || cfg.ProviderConfig["domain"] != deploymentDomain ||
			access["accessKeyId"] != configSentinel || cert == "" || key == "" {
			t.Error("deployer received unapproved inputs")
		}
		if transfers.Add(1) == 1 {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})
	for _, token := range []string{"", f.interfaceKey, session(t, f.member)} {
		expectDenied(t, f.request(http.MethodGet, deploymentPath, token, "", ""))
		expectDenied(t, f.request(http.MethodPost, deploymentPath, token, "application/json", "{}"))
	}

	w := f.call(t, http.MethodGet, "/targets?workflowId="+f.workflow.Id, nil, http.StatusOK)
	var targets struct{ Items []struct{ NodeID string } }
	readJSON(t, w, &targets)
	if len(targets.Items) != 1 || targets.Items[0].NodeID != "ship" {
		t.Fatal("target picker included disabled, unknown or draft targets")
	}
	order := f.order(t)
	options := f.config(order)
	options["nodeId"] = "draft-target"
	f.call(t, http.MethodPost, "", options, http.StatusNotFound)
	options["nodeId"] = "ship"
	options["command"] = "synthetic-rejected"
	f.call(t, http.MethodPost, "", options, http.StatusBadRequest)
	delete(options, "command")
	options["confirmed"] = false
	f.call(t, http.MethodPost, "", options, http.StatusBadRequest)
	options["confirmed"] = true

	fromOtherOrigin := httptest.NewRequest(http.MethodPost, deploymentPath, strings.NewReader(testJSON(t, options)))
	fromOtherOrigin.Header.Set("Origin", "https://other.example.test")
	fromOtherOrigin.Header.Set("Authorization", "Bearer "+f.token)
	w = httptest.NewRecorder()
	f.mux.ServeHTTP(w, fromOtherOrigin)
	expectStatus(t, w, http.StatusForbidden)

	id := f.add(t, options)
	st := f.state(t, id)
	if st.Active || st.Automatic || st.OrderID != order || st.Status != 0 {
		t.Fatal("native creation armed a deployment")
	}
	f.call(t, http.MethodPost, "/"+id+"/process", fields{"version": st.Version, "confirmed": true}, http.StatusConflict)
	f.active(t, id, true)
	st = f.state(t, id)
	f.call(t, http.MethodPost, "/"+id+"/process", fields{"version": st.Version}, http.StatusBadRequest)
	payload := testJSON(t, fields{"version": st.Version, "confirmed": true})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- f.request(http.MethodPost, deploymentPath+"/"+id+"/process", f.token, "application/json", payload)
	}()
	defer close(release)
	select {
	case <-started:
	case response := <-done:
		t.Fatalf("delivery did not reach synthetic provider (HTTP %d)", response.Code)
	case <-time.After(5 * time.Second):
		t.Fatal("delivery did not reach synthetic provider")
	}
	inFlight := f.state(t, id)
	if inFlight.Started == 0 || inFlight.Finished != 0 {
		t.Fatal("provider delivery began before a durable claim")
	}
	f.call(t, http.MethodPost, "/"+id+"/process", fields{"version": st.Version, "confirmed": true}, http.StatusConflict)
	f.call(t, http.MethodPost, "/"+id+"/reset", fields{"version": inFlight.Version, "confirmed": true}, http.StatusConflict)
	release <- struct{}{}
	expectStatus(t, <-done, http.StatusOK)
	st = f.state(t, id)
	if transfers.Load() != 1 || st.Status != 1 || !strings.Contains(st.Result, "completed") {
		t.Fatal("a duplicate operation reached the provider or result was lost")
	}
	w = f.call(t, http.MethodGet, "?status=1&orderId="+order+"&accessId="+f.target.Id+"&q=deployment", nil, http.StatusOK)
	var page struct{ Total int }
	readJSON(t, w, &page)
	if page.Total != 1 {
		t.Fatal("deployment filters did not count the matching task")
	}
	next := f.order(t)
	change := f.config(next)
	change["version"] = st.Version
	f.call(t, http.MethodPatch, "/"+id, change, http.StatusBadRequest)
	second := f.add(t, options)
	batch := fields{"action": "rebind", "confirmed": true, "orderId": next,
		"tasks": []fields{{"id": id, "version": st.Version}, {"id": second, "version": 2}}}
	f.call(t, http.MethodPost, "/batch", batch, http.StatusConflict)
	if f.state(t, id).OrderID != order {
		t.Fatal("batch rebind was partially applied")
	}
	batch["tasks"] = []fields{{"id": id, "version": st.Version}, {"id": second, "version": 1}}
	f.call(t, http.MethodPost, "/batch", batch, http.StatusOK)
	st = f.state(t, id)
	if st.OrderID != next {
		t.Fatal("confirmed batch did not rebind the order")
	}
	f.call(t, http.MethodDelete, "/"+id, fields{"confirmed": true, "version": st.Version}, http.StatusOK)
	logs := f.logs(t, id)
	if len(logs) != 1 || logs[0].OrderID != order || logs[0].Trigger != "admin" || logs[0].Outcome != "completed" {
		t.Fatal("rebind or deletion rewrote historical execution evidence")
	}
}

func TestNativeCertificateDeploymentScheduleAndRenewal(t *testing.T) {
	var deliveries int
	failNext := false
	deploy := func(context.Context, domain.WorkflowNodeConfigForBizDeploy, map[string]any, string, string) error {
		deliveries++
		if failNext {
			return errors.New(configSentinel)
		}
		return nil
	}
	f := setupDeployment(t, deploy)
	run := func(want int) {
		t.Helper()
		if err := dnsmcp.RunCertificateDeployments(t.Context(), f.app, deploy); err != nil {
			t.Fatal(err)
		}
		if deliveries != want {
			t.Fatalf("automatic worker reached the synthetic provider %d times, want %d", deliveries, want)
		}
	}
	root, successor := f.order(t), f.order(t)
	channel := f.save(t, "access", fields{"name": "Synthetic deployment notices", "provider": "sendcloud",
		"reserve": "notif", "config": fields{"secret": configSentinel}})
	for _, order := range []string{root, successor} {
		if _, err := f.app.DB().Insert("dns_cert_notice_settings", dbx.Params{"order_id": order, "access_id": channel.Id}).Execute(); err != nil {
			t.Fatal(err)
		}
	}
	// Default policy retains disabled automation for pre-existing active tasks.
	_, err := f.app.DB().Insert("dns_cert_deploy", dbx.Params{"id": "old-task", "access_id": f.target.Id,
		"order_id": root, "workflow_id": f.workflow.Id, "node_id": "ship", "created": 1}).Execute()
	if err != nil {
		t.Fatal(err)
	}
	run(0)
	options := f.config(root)
	options["automatic"], options["followRenewal"] = true, true
	f.call(t, http.MethodPost, "", options, http.StatusConflict)
	_, err = f.app.DB().Insert("dns_cert_renewals", dbx.Params{"root_id": root, "current_id": root,
		"access_id": f.issuer.Id, "domain": deploymentDomain, "zone_id": f.visible.Id, "zone_account": f.account.Id,
		"zone_provider": "cloudflare", "zone_remote": "first", "zone_name": "allowed.example",
		"enabled": true, "status": "scheduled", "next_at": time.Now().Add(time.Hour).Unix()}).Execute()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{root, successor} {
		if _, err = f.app.DB().Insert("dns_cert_renewal_orders", dbx.Params{"order_id": id, "root_id": root}).Execute(); err != nil {
			t.Fatal(err)
		}
	}
	task := f.add(t, options)
	run(0)
	f.active(t, task, true)
	f.active(t, task, false)
	run(0)
	f.active(t, task, true)
	// Editing the stored target config invalidates approval even with an identical updated timestamp.
	_, err = f.app.DB().Update("access", dbx.Params{"config": `{"accessKeyId":"rotated-synthetic-value"}`},
		dbx.HashExp{"id": f.target.Id}).Execute()
	if err != nil {
		t.Fatal(err)
	}
	st := f.state(t, task)
	if !st.Automatic || !st.FollowRenewal || st.PolicyCurrent {
		t.Fatal("credential change left automatic delivery approved")
	}
	run(0)
	options["version"] = st.Version
	f.call(t, http.MethodPatch, "/"+task, options, http.StatusOK)
	run(1)
	run(1)
	_, err = f.app.DB().Update("dns_cert_renewals", dbx.Params{"current_id": successor}, dbx.HashExp{"root_id": root}).Execute()
	if err != nil {
		t.Fatal(err)
	}
	failNext = true
	run(2)
	run(2)
	st = f.state(t, task)
	if st.OrderID != successor || st.Status != -1 {
		t.Fatal("renewal was not followed or ambiguous write was not recorded")
	}
	f.call(t, http.MethodPost, "/"+task+"/process", fields{"confirmed": true, "version": st.Version, "runAgain": true}, http.StatusConflict)
	f.call(t, http.MethodPost, "/"+task+"/reset", fields{"confirmed": true, "version": st.Version}, http.StatusConflict)
	f.call(t, http.MethodPost, "/"+task+"/reset", fields{"confirmed": true, "version": st.Version, "reconciled": true}, http.StatusOK)
	if f.state(t, task).Automatic {
		t.Fatal("reset rearmed automatic delivery")
	}
	run(2)
	var outcomesWithNotice int
	err = f.app.DB().NewQuery("SELECT count(*) FROM dns_cert_notices WHERE action='deployment' AND access_id={:id} AND status='pending'").
		Bind(dbx.Params{"id": channel.Id}).Row(&outcomesWithNotice)
	if err != nil || outcomesWithNotice != 2 {
		t.Fatal("expected one queued notice for each of the completed and ambiguous attempts")
	}
	if _, err := f.app.DB().Update("dns_cert_notices", dbx.Params{"status": "retrying"}, dbx.HashExp{"action": "deployment"}).Execute(); err != nil {
		t.Fatal(err)
	}
	run(2)
	logs := f.logs(t, task)
	outcomes := map[string]string{}
	for _, entry := range logs {
		if entry.Trigger != "schedule" {
			t.Fatal("automatic attempt used an incorrect audit source")
		}
		outcomes[entry.OrderID] = entry.Outcome
	}
	if len(logs) != 2 || outcomes[root] != "completed" || outcomes[successor] != "needs_reconciliation" {
		t.Fatal("automatic attempts lost their immutable issued orders or outcomes")
	}
}
