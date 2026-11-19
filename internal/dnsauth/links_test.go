package dnsauth_test

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/domain"
)

func TestQuickLoginAndPasswordRevocation(t *testing.T) {
	app := setup(t)
	const current = "synthetic-password-to-change"
	member := save(t, app, dnsauth.Members, map[string]any{"email": "member@example.test", "password": current, "apiEnabled": true})
	access := save(t, app, "access", map[string]any{"name": "test", "provider": "cloudflare", "config": map[string]string{"token": "synthetic-only"}})
	a := save(t, app, "dnsAccount", map[string]any{"id": access.Id, "accessRef": access.Id})
	z := save(t, app, "dnsZone", map[string]any{"name": "sample.test", "providerZoneId": "only", "accountRef": a.Id, "present": true, "quickLoginEnabled": true})
	off := save(t, app, "dnsZone", map[string]any{"name": "other.test", "providerZoneId": "other", "accountRef": a.Id, "present": true})
	grant := save(t, app, "dns_zone_grants", map[string]any{"member": member.Id, "zone": z.Id, "role": "editor"})
	save(t, app, "dns_zone_grants", map[string]any{"member": member.Id, "zone": off.Id, "role": "reader"})
	actor := &core.RequestEvent{App: app, Auth: member}
	actor.Request = httptest.NewRequest("POST", "/", nil)
	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	dnsauth.Bind(router.Group("/api"))
	mux, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	link := func(id string, write bool, uid string) string {
		t.Helper()
		hash, err := dnsauth.IssueQuickLink(actor, id, write, uid)
		if err != nil {
			t.Fatalf("issue zone ticket: %v", err)
		}
		if !strings.HasPrefix(hash, "#/dns-member?ticket=") {
			t.Fatal("missing fragment ticket")
		}
		return strings.TrimPrefix(hash, "#/dns-member?ticket=")
	}
	redeem := func(ticket string, allowed bool) string {
		t.Helper()
		status, body := request(t, mux, "POST", "/api/dns-member/redeem", "", `{"ticket":"`+ticket+`"}`)
		var result struct {
			Code int
			Data struct {
				Token  string
				Record struct{ CollectionName string }
			}
		}
		if status != 200 || json.Unmarshal([]byte(body), &result) != nil {
			t.Fatal("invalid response")
		}
		if !allowed {
			if result.Code != 403 || result.Data.Token != "" {
				t.Fatal("invalid ticket accepted")
			}
			return ""
		}
		if result.Code != 0 || result.Data.Token == "" || result.Data.Record.CollectionName != dnsauth.ZoneSessions {
			t.Fatalf("expected zone-only login, code %d", result.Code)
		}
		return result.Data.Token
	}
	list := func(token string, count int, writable bool) {
		t.Helper()
		status, body := request(t, mux, "GET", "/api/dns-member/zones", token, "")
		var result struct {
			Code int
			Data struct {
				Total int
				Items []dnsauth.Zone
			}
		}
		if count == 0 && status == 401 {
			return
		}
		if status != 200 || json.Unmarshal([]byte(body), &result) != nil {
			t.Fatalf("invalid metadata response %d", status)
		}
		if count == 0 && result.Code == 404 {
			return
		}
		if result.Code != 0 || result.Data.Total != count || len(result.Data.Items) != count {
			t.Fatalf("listed %d expected %d, code %d", result.Data.Total, count, result.Code)
		}
		if count > 0 && (result.Data.Items[0].ID != z.Id || result.Data.Items[0].CanWrite != writable) {
			t.Fatal("invalid delegated grant")
		}
	}
	if _, err := dnsauth.IssueQuickLink(actor, off.Id, false, ""); !domain.IsRecordNotFoundError(err) {
		t.Fatal("disabled zone link issued")
	}
	expired := link(z.Id, false, "")
	if _, err := app.DB().NewQuery("UPDATE dns_zone_sessions SET ticketUntil=1 WHERE zone={:z}").Bind(dbx.Params{"z": z.Id}).Execute(); err != nil {
		t.Fatal(err)
	}
	redeem(expired, false)
	readerTicket := link(z.Id, false, "")
	token := redeem(readerTicket, true)
	redeem(readerTicket, false)
	list(token, 1, false)
	for _, path := range []string{"/api/collections/dns_zone_sessions/records", "/api/collections/access/records", "/api/collections/dns_members/records"} {
		if status, _ := request(t, mux, "GET", path, token, ""); status < 400 {
			t.Fatalf("collection exposed at %s", path)
		}
	}
	if status, _ := request(t, mux, "POST", "/api/dns-member/zones/"+z.Id+"/links", token, `{"write":false}`); status < 400 {
		t.Fatal("zone session could delegate")
	}
	writer := redeem(link(z.Id, true, ""), true)
	list(writer, 1, true)
	grant.Set("role", "reader")
	if err := app.Save(grant); err != nil {
		t.Fatal(err)
	}
	list(writer, 1, false)
	if _, err := dnsauth.IssueQuickLink(actor, z.Id, true, ""); err == nil {
		t.Fatal("reader issued writer link")
	}
	z.Set("quickLoginEnabled", false)
	if err := app.Save(z); err != nil {
		t.Fatal(err)
	}
	z.Set("quickLoginEnabled", true)
	if err := app.Save(z); err != nil {
		t.Fatal(err)
	}
	list(token, 0, false)
	list(writer, 0, false)

	const key = "123"
	insertKey := func(actions []string) {
		t.Helper()
		data, _ := json.Marshal(map[string]any{"actions": actions, "zones": []string{z.Id}, "interfaces": []string{"mcp"}})
		_, err := app.DB().Insert("dns_interface_keys", dbx.Params{"uid": key, "label": "synthetic", "owner_collection": dnsauth.Members, "owner": member.Id, "scope": string(data)}).Execute()
		if err != nil {
			t.Fatal(err)
		}
	}
	removeKey := func() {
		t.Helper()
		if _, err := app.DB().Delete("dns_interface_keys", dbx.HashExp{"uid": key}).Execute(); err != nil {
			t.Fatal(err)
		}
	}
	insertKey([]string{"record.read", "domain.read"})
	if _, err := dnsauth.IssueQuickLink(actor, z.Id, false, key); err == nil {
		t.Fatal("issued with ungranted interface action")
	}
	removeKey()
	insertKey([]string{"domain.login", "record.read", "domain.read"})
	if _, err := dnsauth.IssueQuickLink(actor, z.Id, true, key); err == nil {
		t.Fatal("writable interface ticket issued")
	}
	apiToken := redeem(link(z.Id, false, key), true)
	list(apiToken, 1, false)
	member.Set("apiEnabled", false)
	if err := app.Save(member); err != nil {
		t.Fatal(err)
	}
	member.Set("apiEnabled", true)
	if err := app.Save(member); err != nil {
		t.Fatal(err)
	}
	list(apiToken, 0, false)
	var keyCount int
	if err := app.DB().Select("COUNT(*)").From("dns_interface_keys").Row(&keyCount); err != nil || keyCount != 0 {
		t.Fatal("disabled interface keys not revoked")
	}

	outstandingTicket := link(z.Id, false, "")
	signedIn := redeem(link(z.Id, false, ""), true)
	memberToken, err := member.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	_, body := request(t, mux, "POST", "/api/dns-member/password", memberToken, `{"current":"wrong-password","password":"new-synthetic-password"}`)
	if !strings.Contains(body, `"code":403`) {
		t.Fatal("expected old password challenge")
	}
	_, body = request(t, mux, "POST", "/api/dns-member/password", memberToken, `{"current":"`+current+`","password":"new-synthetic-password"}`)
	if !strings.Contains(body, `"code":0`) {
		t.Fatal("valid password change failed")
	}
	if status, _ := request(t, mux, "GET", "/api/dns-member/zones", memberToken, ""); status != 401 {
		t.Fatalf("old member token still accepted: %d", status)
	}
	list(signedIn, 0, false)
	redeem(outstandingTicket, false)
}
