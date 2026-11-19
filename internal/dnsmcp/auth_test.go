// DNSMgr's public wire format is exercised here through the real PocketBase
// middleware, with synthetic credentials and a provider that never uses a network.
package dnsmcp_test

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/logger"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/dnsmcp"
	_ "github.com/certimate-go/certimate/migrations"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type fields = map[string]any

const configSentinel = "synthetic-provider-only-test-value"
const listToolsRequest = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

type authFixture struct {
	app             *core.BaseApp
	mux             http.Handler
	admin, member   *core.Record
	account         *core.Record
	visible, hidden *core.Record
	grant           *core.Record
	resolutions     int
	provider        interfaceProvider
}

type interfaceProvider struct {
	dns.Provider
	created []dns.RecordInput
	zone    string
}

func (p *interfaceProvider) CreateDNSRecord(_ context.Context, zone string, in dns.RecordInput) (string, error) {
	p.zone = zone
	p.created = append(p.created, in)
	return "synthetic-record", nil
}

func (*interfaceProvider) DNSRecords(_ context.Context, zone string, page int, _ string) (*dns.DNSPage[dns.DNSRecord], error) {
	return &dns.DNSPage[dns.DNSRecord]{Items: []dns.DNSRecord{}, Info: dns.PageInfo{Page: page, Total: 0}}, nil
}

func (*interfaceProvider) ZoneDetails(_ context.Context, _ string) (*dns.ZoneDetails, error) {
	return &dns.ZoneDetails{Name: "allowed.example", Lines: []dns.RecordLine{{ID: "default", Name: "Default"}}, MinTTL: 300}, nil
}

func setupInterface(t *testing.T) *authFixture {
	t.Helper()
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.ResetBootstrapState() })
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	save := func(collection string, values fields) *core.Record {
		t.Helper()
		c, err := app.FindCollectionByNameOrId(collection)
		if err != nil {
			t.Fatal(err)
		}
		r := core.NewRecord(c)
		for k, v := range values {
			r.Set(k, v)
		}
		if err := app.Save(r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	f := &authFixture{app: app}
	f.admin = save(core.CollectionNameSuperusers, fields{"email": "admin@example.test", "password": "synthetic-admin-password"})
	f.member = save(dnsauth.Members, fields{"email": "member@example.test", "password": "synthetic-member-password", "apiEnabled": true})
	f.account = save("access", fields{"provider": "cloudflare", "name": "Integration test", "config": fields{"apiToken": configSentinel}})
	save("dnsAccount", fields{"id": f.account.Id, "accessRef": f.account.Id})
	f.visible = save("dnsZone", fields{"accountRef": f.account.Id, "providerZoneId": "first", "name": "allowed.example", "present": true})
	f.hidden = save("dnsZone", fields{"accountRef": f.account.Id, "providerZoneId": "second", "name": "hidden.example", "present": true})
	f.grant = save("dns_zone_grants", fields{"member": f.member.Id, "zone": f.visible.Id, "role": "reader"})

	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	dnsmcp.Bind(router.RouterGroup, func(_ context.Context, provider, access string, _ bool) (dns.Provider, error) {
		f.resolutions++
		if provider != "cloudflare" || access != f.account.Id {
			t.Fatal("wrong provider binding")
		}
		return &f.provider, nil
	}, dnsmcp.Services{})
	f.mux, err = router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *authFixture) request(method, path, authorization, contentType, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w
}

func expectStatus(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		// Response payloads can include freshly issued credentials.
		t.Fatalf("got HTTP %d, want %d", w.Code, status)
	}
}

func expectDenied(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code < 400 || w.Code >= 500 {
		t.Fatalf("request should be denied, got HTTP %d", w.Code)
	}
}

func readJSON(t *testing.T, w *httptest.ResponseRecorder, out any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
		t.Fatal("invalid response JSON")
	}
}

func testJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func session(t *testing.T, r *core.Record) string {
	t.Helper()
	token, err := r.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

type credential struct {
	UID    string `json:"uid"`
	APIKey string `json:"apikey"`
}

func (k credential) bearer() string { return "Bearer " + k.UID + ":" + k.APIKey }

// Generate the signature like the legacy client. This deliberately does not
// share any signing or parsing code with the server.
func (k credential) form(stamp time.Time) url.Values {
	ts := strconv.FormatInt(stamp.Unix(), 10)
	sum := md5.Sum([]byte(k.UID + ts + k.APIKey))
	return url.Values{"uid": {k.UID}, "timestamp": {ts}, "sign": {hex.EncodeToString(sum[:])}}
}

func (f *authFixture) keyInput(actions, interfaces []string) fields {
	return fields{"label": "synthetic integration", "actions": actions, "interfaces": interfaces, "zones": []string{f.visible.Id}}
}

func (f *authFixture) issue(t *testing.T, actor string, scope fields) credential {
	t.Helper()
	w := f.request("POST", "/api/dns-keys", actor, "application/json", testJSON(t, scope))
	expectStatus(t, w, 201)
	var k credential
	readJSON(t, w, &k)
	n, err := strconv.ParseUint(k.UID, 10, 53)
	if k.APIKey == "" || err != nil || n == 0 || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("invalid issued credential or missing cache restriction")
	}
	return k
}

func (f *authFixture) selectedActions(t *testing.T, token string) []string {
	t.Helper()
	w := f.request("GET", "/api/dns-keys/actions", token, "", "")
	expectStatus(t, w, 200)
	var result []string
	readJSON(t, w, &result)
	if !slices.Contains(result, "domain.read") {
		t.Fatal("actor is missing the domain read permission")
	}
	return result
}

func (f *authFixture) tools(t *testing.T, key credential) ([]string, int) {
	t.Helper()
	w := f.request("POST", "/mcp", key.bearer(), "application/json", listToolsRequest)
	expectStatus(t, w, 200)
	var result struct {
		Result struct {
			Tools []struct {
				Name        string
				InputSchema struct {
					Type       string
					Properties struct {
						Action *struct{ Enum []string }
					}
				}
			}
		}
	}
	readJSON(t, w, &result)
	names := make([]string, 0, len(result.Result.Tools))
	actionCount := 0
	for _, entry := range result.Result.Tools {
		if entry.InputSchema.Type != "object" || slices.Contains(names, entry.Name) {
			t.Fatal("invalid or duplicated tool definition")
		}
		names = append(names, entry.Name)
		action := entry.InputSchema.Properties.Action
		if action == nil {
			// DNSMgr omits the action selector on single-operation tools.
			actionCount++
		} else {
			actionCount += len(action.Enum)
		}
	}
	slices.Sort(names)
	return names, actionCount
}

func (f *authFixture) postForm(path string, v url.Values) *httptest.ResponseRecorder {
	return f.request("POST", path, "", "application/x-www-form-urlencoded", v.Encode())
}

func TestInterfaceKeySchemasAndActorIsolation(t *testing.T) {
	f := setupInterface(t)
	admin := session(t, f.admin)
	member := session(t, f.member)
	permitted := f.selectedActions(t, admin)
	limited := f.selectedActions(t, member)
	if len(permitted) <= len(limited) {
		t.Fatal("administrative action list is not distinguished from member capabilities")
	}
	all := f.keyInput(permitted, []string{"mcp"})
	all["global"] = true
	all["accounts"] = []string{f.account.Id}
	full := f.issue(t, admin, all)

	expected := strings.Fields("cert_account_manage cert_account_query cert_cname_manage cert_cname_query cert_deploy_manage cert_deploy_query cert_order_manage cert_order_query cf_hostname_manage cf_hostname_query cf_tunnel_manage cf_tunnel_query dmonitor_manage dmonitor_query dns_account_manage dns_account_query domain_category_manage domain_manage domain_query get_overview list_provider_types operation_log_query optimizeip_manage optimizeip_query record_manage record_query schedule_manage schedule_query")
	if got, actionCount := f.tools(t, full); !slices.Equal(got, expected) || actionCount != 124 {
		t.Fatalf("unexpected MCP catalog: %d actions across %v", actionCount, got)
	}
	resources := f.keyInput([]string{"domain.read"}, []string{"mcp"})
	scoped := f.issue(t, member, resources)
	if got, _ := f.tools(t, scoped); !slices.Equal(got, []string{"domain_query"}) {
		t.Fatalf("unexpected member tool list: %v", got)
	}
	for _, scope := range []fields{
		all,
		{"label": "global", "interfaces": []string{"mcp"}, "actions": []string{"domain.read"}, "zones": []string{f.visible.Id}, "global": true},
		{"label": "account", "interfaces": []string{"mcp"}, "actions": []string{"domain.read"}, "zones": []string{f.visible.Id}, "accounts": []string{f.account.Id}},
		f.keyInput([]string{"record.delete"}, []string{"mcp"}),
		{"label": "foreign", "interfaces": []string{"mcp"}, "actions": []string{"domain.read"}, "zones": []string{f.hidden.Id}},
	} {
		expectDenied(t, f.request("POST", "/api/dns-keys", member, "application/json", testJSON(t, scope)))
	}
	for _, token := range []string{admin, member, "", "Bearer " + admin} {
		expectDenied(t, f.request("POST", "/mcp", token, "application/json", listToolsRequest))
		expectDenied(t, f.request("POST", "/api/domain", token, "application/json", "{}"))
	}
	expectDenied(t, f.request("GET", "/api/dns-keys", full.bearer(), "", ""))
	expectDenied(t, f.request("GET", "/api/collections/access/records", full.bearer(), "", ""))
	expectDenied(t, f.postForm("/api/domain", full.form(time.Now())))
	onlyAPI := f.issue(t, member, f.keyInput([]string{"domain.read"}, []string{"api"}))
	expectDenied(t, f.request("POST", "/api/domain", onlyAPI.bearer(), "application/json", "{}"))
	expectDenied(t, f.request("POST", "/mcp", onlyAPI.bearer(), "application/json", listToolsRequest))

	for _, op := range []struct{ tool, action, id string }{
		{"domain_query", "get", f.hidden.Id}, {"cert_order_query", "list", ""}, {"record_manage", "delete", f.visible.Id},
	} {
		body := testJSON(t, fields{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": fields{
			"name": op.tool, "arguments": fields{"action": op.action, "id": op.id, "domain_id": op.id, "recordid": "one"},
		}})
		w := f.request("POST", "/mcp", scoped.bearer(), "application/json", body)
		var result struct{ Result struct{ IsError bool } }
		readJSON(t, w, &result)
		if !result.Result.IsError || strings.Contains(w.Body.String(), "hidden.example") {
			t.Fatal("guessed resource or action visible to member")
		}
	}
	// The owner can administer both zones, but this signed credential can only
	// list and inspect one. Its action and zone grants still apply.
	adminRead := f.issue(t, admin, f.keyInput([]string{"domain.read"}, []string{"api"}))
	signedRead := adminRead.form(time.Now())
	page := f.postForm("/api/domain", signedRead)
	expectStatus(t, page, 200)
	var listing struct {
		Total int
		Rows  []struct{ Name string }
	}
	readJSON(t, page, &listing)
	if listing.Total != 1 || len(listing.Rows) != 1 || listing.Rows[0].Name != "allowed.example" {
		t.Fatal("superuser's signed credential escaped its zone scope")
	}
	expectDenied(t, f.postForm("/api/domain/"+f.hidden.Id, signedRead))
	expectDenied(t, f.postForm("/api/record/delete/"+f.visible.Id, signedRead))
	if f.resolutions != 0 {
		t.Fatal("provider was contacted for a denied operation")
	}
	for _, origin := range []string{"https://other.example", "http://app.example"} {
		r := httptest.NewRequest("POST", "https://app.example/mcp", strings.NewReader(listToolsRequest))
		r.Header.Set("Authorization", full.bearer())
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		f.mux.ServeHTTP(w, r)
		expectDenied(t, w)
	}
	f.app.Settings().SuperuserIPs = []string{"127.0.0.1"}
	if err := f.app.Save(f.app.Settings()); err != nil {
		t.Fatal(err)
	}
	expectDenied(t, f.request("POST", "/mcp", full.bearer(), "application/json", listToolsRequest))
	// The default httptest request comes from a non-loopback IP. A member
	// credential on the same route remains subject to member grants.
	if got, _ := f.tools(t, scoped); !slices.Equal(got, []string{"domain_query"}) {
		t.Fatal("superuser IP policy affected an unrelated member")
	}
}

func TestLegacySignedRequestsAndKeyLifecycle(t *testing.T) {
	f := setupInterface(t)
	member := session(t, f.member)
	admin := session(t, f.admin)
	k := f.issue(t, member, f.keyInput([]string{"domain.read", "record.read"}, []string{"api", "mcp"}))
	signed := k.form(time.Now())
	domains := func(key url.Values, total int) string {
		t.Helper()
		w := f.postForm("/api/domain", key)
		expectStatus(t, w, 200)
		var result struct {
			Total int
			Rows  []struct {
				ID   json.RawMessage
				Name string
			}
		}
		readJSON(t, w, &result)
		if result.Total != total || len(result.Rows) != total || strings.Contains(w.Body.String(), configSentinel) || strings.Contains(w.Body.String(), "hidden.example") {
			t.Fatal("domain result leaked data or computed count outside grant")
		}
		if total == 0 {
			return ""
		}
		if result.Rows[0].Name != "allowed.example" {
			t.Fatal("wrong granted domain")
		}
		id := strings.Trim(string(result.Rows[0].ID), `"`)
		if n, err := strconv.ParseUint(id, 10, 63); err != nil || n == 0 {
			t.Fatal("legacy domain list did not return a positive numeric domain ID")
		}
		return id
	}
	id := domains(signed, 1)
	if domains(signed, 1) != id {
		t.Fatal("legacy domain ID changed between requests")
	}
	for _, path := range []string{"/api/domain/" + id, "/api/record/data/" + id} {
		expectStatus(t, f.postForm(path, signed), 200)
	}
	expectDenied(t, f.postForm("/api/domain/"+f.hidden.Id, signed))
	expectDenied(t, f.postForm("/api/domain", k.form(time.Now().Add(-10*time.Minute))))
	expectDenied(t, f.postForm("/api/domain", k.form(time.Now().Add(10*time.Minute))))
	expectDenied(t, f.postForm("/api/domain?"+signed.Encode(), nil))
	duplicate := k.form(time.Now())
	duplicate.Add("uid", k.UID)
	expectDenied(t, f.postForm("/api/domain", duplicate))

	own := f.request("GET", "/api/dns-keys", member, "", "")
	expectStatus(t, own, 200)
	if !strings.Contains(own.Body.String(), k.UID) || strings.Contains(own.Body.String(), k.APIKey) {
		t.Fatal("owner's key metadata is incorrect")
	}
	other := f.request("GET", "/api/dns-keys", admin, "", "")
	expectStatus(t, other, 200)
	if strings.Contains(other.Body.String(), k.UID) {
		t.Fatal("another actor's key is visible")
	}
	f.request("DELETE", "/api/dns-keys/"+k.UID, admin, "", "")
	domains(signed, 1)
	if err := f.app.Delete(f.grant); err != nil {
		t.Fatal(err)
	}
	domains(signed, 0)
	before := f.resolutions
	expectDenied(t, f.postForm("/api/record/data/"+id, signed))
	if f.resolutions != before {
		t.Fatal("provider contacted after live zone grant removal")
	}

	if err := f.app.Logger().Handler().(*logger.BatchHandler).WriteAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	var logs []core.Log
	if err := f.app.LogQuery().All(&logs); err != nil || len(logs) == 0 {
		t.Fatal("could not inspect persisted request logs")
	}
	logJSON := testJSON(t, logs)
	for _, forbidden := range []string{k.APIKey, signed.Get("sign"), configSentinel} {
		if strings.Contains(logJSON, forbidden) {
			t.Fatal("credential material persisted in request logs")
		}
	}
	rows, err := f.app.DB().NewQuery("SELECT * FROM dns_interface_keys").Rows()
	if err != nil {
		t.Fatal(err)
	}
	meta := dbx.NullStringMap{}
	if !rows.Next() || rows.ScanMap(meta) != nil || rows.Next() || rows.Err() != nil {
		rows.Close()
		t.Fatal("unexpected persisted credential rows")
	}
	rows.Close()
	if strings.Contains(testJSON(t, meta), k.APIKey) {
		t.Fatal("interface secret persisted in the key table")
	}
	expectStatus(t, f.request("DELETE", "/api/dns-keys/"+k.UID, member, "", ""), 204)
	expectDenied(t, f.postForm("/api/domain", signed))
	expectDenied(t, f.request("POST", "/mcp", k.bearer(), "application/json", listToolsRequest))
}

func TestDisabledMemberCannotReuseInterfaceKey(t *testing.T) {
	f := setupInterface(t)
	k := f.issue(t, session(t, f.member), f.keyInput([]string{"domain.read"}, []string{"mcp"}))
	f.member.Set("apiEnabled", false)
	if err := f.app.Save(f.member); err != nil {
		t.Fatal(err)
	}
	expectDenied(t, f.request("POST", "/mcp", k.bearer(), "application/json", listToolsRequest))
	expectDenied(t, f.request("GET", "/api/dns-keys/actions", session(t, f.member), "", ""))
	expectDenied(t, f.request("POST", "/api/dns-keys", session(t, f.member), "application/json", testJSON(t, f.keyInput([]string{"domain.read"}, []string{"api"}))))
	f.member.Set("apiEnabled", true)
	if err := f.app.Save(f.member); err != nil {
		t.Fatal(err)
	}
	// Issue another key after the owner regains API access to independently
	// exercise the disabled-account and token-rotation paths.
	k = f.issue(t, session(t, f.member), f.keyInput([]string{"domain.read"}, []string{"mcp"}))
	f.member.Set("disabled", true)
	if err := f.app.Save(f.member); err != nil {
		t.Fatal(err)
	}
	expectDenied(t, f.request("POST", "/mcp", k.bearer(), "application/json", listToolsRequest))
	member, err := f.app.FindRecordById(dnsauth.Members, f.member.Id)
	if err != nil {
		t.Fatal(err)
	}
	member.Set("disabled", false)
	if err := f.app.Save(member); err != nil {
		t.Fatal(err)
	}
	expectDenied(t, f.request("POST", "/mcp", k.bearer(), "application/json", listToolsRequest))
}

// Sign the same fields a client sends. Non-ASCII text and reserved URL-form
// characters exercise canonical escaping independent of the server's helper.
func signedWrite(k credential, path, nonce string) url.Values {
	form := url.Values{
		"name": {"note"}, "type": {"TXT"},
		"ttl": {"600"}, "value": {"example + ü & ="},
	}
	return signInterfaceForm(k, path, nonce, form)
}

func signInterfaceForm(k credential, path, nonce string, form url.Values) url.Values {
	form.Set("uid", k.UID)
	form.Set("timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	form.Set("sign_version", "2")
	form.Set("nonce", nonce)
	mac := hmac.New(sha256.New, []byte(k.APIKey))
	mac.Write([]byte("DNSMgr-v2\nPOST\n" + path + "\n" + form.Encode()))
	form.Set("sign", hex.EncodeToString(mac.Sum(nil)))
	return form
}

func TestSignedMutationBindsPathParametersAndNonce(t *testing.T) {
	f := setupInterface(t)
	admin := session(t, f.admin)
	scope := f.keyInput(f.selectedActions(t, admin), []string{"api"})
	scope["global"] = true
	scope["accounts"] = []string{f.account.Id}
	k := f.issue(t, admin, scope)
	f.visible.Set("quickLoginEnabled", true)
	if err := f.app.Save(f.visible); err != nil {
		t.Fatal(err)
	}

	w := f.postForm("/api/domain", k.form(time.Now()))
	expectStatus(t, w, http.StatusOK)
	var domains struct{ Rows []struct{ ID json.Number } }
	readJSON(t, w, &domains)
	if len(domains.Rows) != 1 || domains.Rows[0].ID.String() == "" {
		t.Fatal("could not resolve numeric DNSMgr ID")
	}
	id := domains.Rows[0].ID.String()
	add := "/api/record/add/" + id
	for _, operation := range []string{"add", "update", "delete", "status", "remark", "batch"} {
		t.Run("legacy_"+operation, func(t *testing.T) {
			form := k.form(time.Now())
			form.Set("name", "note")
			form.Set("type", "TXT")
			form.Set("value", "legacy")
			expectStatus(t, f.postForm("/api/record/"+operation+"/"+id, form), http.StatusForbidden)
		})
	}
	expectStatus(t, f.postForm("/api/cert/order", k.form(time.Now())), http.StatusForbidden)
	login := k.form(time.Now())
	login.Set("loginurl", "1")
	expectStatus(t, f.postForm("/api/domain/"+id, login), http.StatusForbidden)

	bodyChanged := signedWrite(k, add, "0123456789abcdef0123456789abcdef")
	bodyChanged.Set("value", "altered")
	expectStatus(t, f.postForm(add, bodyChanged), http.StatusForbidden)
	pathChanged := signedWrite(k, add, "ffeeddccbbaa99887766554433221100")
	expectStatus(t, f.postForm("/api/record/update/"+id, pathChanged), http.StatusForbidden)
	badNonce := signedWrite(k, add, "invalid")
	expectStatus(t, f.postForm(add, badNonce), http.StatusForbidden)
	if f.resolutions != 0 || len(f.provider.created) != 0 {
		t.Fatal("an invalid signed mutation reached the provider")
	}

	valid := signedWrite(k, add, "aabbccddeeff00112233445566778899")
	expectStatus(t, f.postForm(add, valid), http.StatusOK)
	if len(f.provider.created) != 1 || f.provider.zone != "first" || f.provider.created[0].Content != valid.Get("value") || f.provider.created[0].Name != "note.allowed.example" {
		t.Fatal("valid signature did not create the expected scoped record")
	}
	before := f.resolutions
	expectStatus(t, f.postForm(add, valid), http.StatusForbidden)
	if f.resolutions != before || len(f.provider.created) != 1 {
		t.Fatal("the same signed mutation reached the provider a second time")
	}
}
