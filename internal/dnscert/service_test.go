package dnscert

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
)

func TestOrderHTTPPermissionsAndDraft(t *testing.T) {
	f := setupRenewal(t)
	router, err := apis.NewRouter(f.app)
	if err != nil {
		t.Fatal(err)
	}
	f.s.bind(router.Group("/api"))
	mux, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	admins, err := f.app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		t.Fatal(err)
	}
	admin := core.NewRecord(admins)
	admin.SetEmail("test-issuer@example.test")
	admin.SetPassword("synthetic-order-test-password")
	if err := f.app.Save(admin); err != nil {
		t.Fatal(err)
	}
	token, err := admin.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string, auth bool) (int, string) {
		t.Helper()
		req := httptest.NewRequest(method, "/api/dnscert"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if auth {
			req.Header.Set("Authorization", token)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	for _, path := range []string{"/accounts", "/orders", "/orders/" + f.original.ID, "/orders/" + f.original.ID + "/events", "/zones?domain=www.example.test"} {
		status, _ := request(http.MethodGet, path, "", false)
		if status != 401 {
			t.Fatalf("anonymous %s returned %d", path, status)
		}
	}
	status, body := request(http.MethodGet, "/accounts", "", true)
	if status != 200 || !strings.Contains(body, "Synthetic CA") || strings.Contains(body, "secretId") {
		t.Fatalf("invalid account projection: %d", status)
	}
	status, body = request(http.MethodGet, "/zones?domain=unrelated.example.test.evil.test", "", true)
	if status != 200 || strings.Contains(body, f.zone) {
		t.Fatal("listed unrelated zones")
	}
	status, body = request(http.MethodGet, "/zones?domain=Order.Example.Test.", "", true)
	if status != 200 || !strings.Contains(body, f.zone) {
		t.Fatalf("did not list matching zones: %d %s", status, body)
	}
	source := f.zone
	req := OrderRequest{Email: "private-draft-contact@example.test", Algorithm: "EC256", Domain: "order.example.test", SourceZoneID: source}
	data, err := json.Marshal(map[string]any{"accessId": f.original.AccessID, "request": req})
	if err != nil {
		t.Fatal(err)
	}
	status, body = request(http.MethodPost, "/orders", string(data), true)
	var order Order
	if status != 200 || json.Unmarshal([]byte(body), &order) != nil || order.ID == "" || order.PrimaryZoneID != source {
		t.Fatalf("save failed %d %s", status, body)
	}
	for _, path := range []string{"/orders", "/orders/" + order.ID + "/events"} {
		status, body = request(http.MethodGet, path, "", true)
		if status != 200 || strings.Contains(body, req.Email) {
			t.Fatalf("bad low-detail projection %s (%d)", path, status)
		}
	}
	status, body = request(http.MethodGet, "/orders/"+order.ID, "", true)
	if status != 200 || !strings.Contains(body, req.Email) {
		t.Fatal("draft editor could not recover contact")
	}
	req.Domain = "another.example.test"
	data, _ = json.Marshal(ActionInput{Version: order.Version, Request: &req})
	status, body = request(http.MethodPost, "/orders/"+order.ID+"/edit", string(data), true)
	if status != 200 || !strings.Contains(body, req.Domain) {
		t.Fatal("draft edit failed", status, body)
	}
	staleStatus, _ := request(http.MethodPost, "/orders/"+order.ID+"/edit", string(data), true)
	if staleStatus != 409 {
		t.Fatal("stale edit accepted", staleStatus)
	}
	if f.issuer.calls != 0 {
		t.Fatal("local draft action contacted issuer")
	}
}

func TestOrderAmbiguousPurchaseAndReset(t *testing.T) {
	f := setupRenewal(t)
	ctx := t.Context()
	req := OrderRequest{Email: "operator@example.test", Algorithm: "EC256", Domain: "order.example.test"}
	order, err := f.s.Draft(ctx, f.app, f.original.AccessID, req)
	if err != nil {
		t.Fatal(err)
	}
	f.issuer.lost = true
	if _, err = f.s.Act(ctx, f.app, order.ID, "create", ActionInput{Version: order.Version}); !errors.Is(err, errProvider) {
		t.Fatal("missing provider error", err)
	}
	order, err = ReadOrder(f.app, order.ID)
	if err != nil {
		t.Fatal(err)
	}
	if order.State != "creating" || !slices.Equal(order.AllowedActions, []string{"recover"}) {
		t.Fatalf("unexpected recoverable state: %+v", order.AllowedActions)
	}
	if _, err = f.s.Act(ctx, f.app, order.ID, "create", ActionInput{Version: order.Version}); !errors.Is(err, errConflict) || f.issuer.reservations != 1 {
		t.Fatal("repeated external reservation")
	}
	order, err = f.s.Act(ctx, f.app, order.ID, "recover", ActionInput{Version: order.Version, RemoteID: "renewed-order"})
	if err != nil || order.State != "pending" {
		t.Fatal("recover", err)
	}
	// Emulate provider cancellation having reached its terminal state.
	_, err = f.app.DB().Update("dns_cert_orders", dbx.Params{"state": "cancelled"}, dbx.HashExp{"id": order.ID}).Execute()
	if err != nil {
		t.Fatal(err)
	}
	next, err := f.s.Act(ctx, f.app, order.ID, "reset", ActionInput{Version: order.Version})
	if err != nil || next.ID == order.ID || next.State != "draft" {
		t.Fatal("terminal reset", err)
	}
	old, err := ReadOrder(f.app, order.ID)
	if err != nil || old.ReplacementID != next.ID || slices.Contains(old.AllowedActions, "reset") {
		t.Fatal("reset linkage missing")
	}
	if _, err = f.s.Act(ctx, f.app, next.ID, "delete", ActionInput{Version: next.Version}); !errors.Is(err, errConflict) {
		t.Fatal("deleted a linked replacement")
	}
	events, err := OrderEvents(ctx, f.app, order.ID, 1)
	if err != nil || events.Total != 4 || events.Items[0].ID <= events.Items[1].ID || events.Items[3].ID < 1 || events.Items[0].Action != "reset" || events.Items[2].Success {
		t.Fatal("order history", events, err)
	}
}
