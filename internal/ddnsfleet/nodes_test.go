package ddnsfleet

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"

	_ "github.com/certimate-go/certimate/migrations"
)

func TestNodeReportLifecycle(t *testing.T) {
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.ResetBootstrapState() })
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	admins, err := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		t.Fatal(err)
	}
	admin := core.NewRecord(admins)
	admin.SetEmail("fleet-test@example.test")
	admin.SetPassword("synthetic-fleet-test-password")
	if err := app.Save(admin); err != nil {
		t.Fatal(err)
	}
	adminToken, err := admin.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	r, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	s := New(nil)
	observedAt := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	var clock atomic.Int64
	clock.Store(observedAt.Unix())
	s.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	s.Bind(r.Group("/api"))
	mux, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	request := func(method, path, token, body string, want int) (http.Header, []byte) {
		t.Helper()
		r, err := http.NewRequest(method, server.URL+"/api/ddns"+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if path == "/report" && len(body) > maxReportBytes {
			// Exercise the streaming limit with no Content-Length.
			r.ContentLength = -1
		}
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("%s %s returned %d, want %d", method, path, response.StatusCode, want)
		}
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.Header, data
	}
	list := func() []NodeView {
		t.Helper()
		_, data := request(http.MethodGet, "/nodes", adminToken, "", http.StatusOK)
		var nodes []NodeView
		if err := json.Unmarshal(data, &nodes); err != nil {
			t.Fatal("invalid node list")
		}
		if strings.Contains(string(data), "token") {
			t.Fatal("node list contains token metadata")
		}
		return nodes
	}
	issue := func(path, body string, want int) IssuedToken {
		t.Helper()
		header, data := request(http.MethodPost, path, adminToken, body, want)
		var result IssuedToken
		if err := json.Unmarshal(data, &result); err != nil || !validToken(result.Token) || result.ID == "" || header.Get("Cache-Control") != "no-store" {
			t.Fatal("invalid enrollment response")
		}
		return result
	}

	request(http.MethodGet, "/nodes", "", "", http.StatusUnauthorized)
	a := issue("/nodes", `{"name":"vm-alpha"}`, http.StatusCreated)
	b := issue("/nodes", `{"name":"vm-beta"}`, http.StatusCreated)
	if a.Token == b.Token {
		t.Fatal("nodes share a device credential")
	}
	var tokenHash string
	if err := app.DB().Select("token_hash").From("ddns_nodes").Where(dbx.HashExp{"id": a.ID}).Row(&tokenHash); err != nil || tokenHash != hashToken(a.Token) {
		t.Fatal("node identity did not persist only its token hash")
	}
	request(http.MethodGet, "/nodes", a.Token, "", http.StatusUnauthorized)
	request(http.MethodPost, "/nodes", a.Token, `{"name":"forbidden"}`, http.StatusUnauthorized)
	request(http.MethodPost, "/nodes/"+a.ID+"/bindings", a.Token, "{}", http.StatusUnauthorized)
	request(http.MethodPost, "/report", adminToken, `{}`, http.StatusUnauthorized)
	if nodes := list(); len(nodes) != 2 || nodes[0].Online || nodes[0].LastSeen != nil || len(nodes[0].Interfaces) != 0 {
		t.Fatal("new node unexpectedly has a report")
	}

	badReports := []string{
		`{"hostname":"vm-a","interfaces":[],"nodeId":"` + b.ID + `"}`,
		`{"hostname":"vm-a","interfaces":[{"name":"eth0","ipv4":["2001:db8::1"]}]}`,
		`{"hostname":"vm-a","interfaces":[{"name":"eth0","ipv6":["::ffff:192.0.2.1"]}]}`,
		`{"hostname":"vm-a","interfaces":[{"name":"eth0","mac":"invalid"}]}`,
		`{"hostname":"vm-a","interfaces":[{"name":"eth0"},{"name":"eth0"}]}`,
		`{"hostname":"vm-a","interfaces":[]} {}`,
	}
	for _, invalid := range badReports {
		request(http.MethodPost, "/report", a.Token, invalid, http.StatusBadRequest)
	}
	request(http.MethodPost, "/report", a.Token, `{"hostname":"`+strings.Repeat("x", maxReportBytes)+`"}`, http.StatusRequestEntityTooLarge)
	const snapshot = `{"hostname":"vm-a","interfaces":[{"name":"ens18","mac":"02-00-5e-10-00-00","ipv4":["192.0.2.12","192.0.2.12"],"ipv6":["2001:0db8::2","2001:db8::1"]},{"name":"dummy0","ipv4":[],"ipv6":[]}]}`
	request(http.MethodPost, "/report", a.Token, snapshot, http.StatusNoContent)
	nodes := list()
	want := []Interface{
		{Name: "dummy0", IPv4: []string{}, IPv6: []string{}},
		{Name: "ens18", MAC: "02:00:5e:10:00:00", IPv4: []string{"192.0.2.12"}, IPv6: []string{"2001:db8::1", "2001:db8::2"}},
	}
	if !nodes[0].Online || nodes[0].Hostname != "vm-a" || nodes[0].LastSeen == nil || !nodes[0].LastSeen.Equal(observedAt) || !reflect.DeepEqual(nodes[0].Interfaces, want) || nodes[1].Online || len(nodes[1].Interfaces) != 0 {
		t.Fatal("report was not normalized and scoped to the reporting node")
	}

	clock.Store(observedAt.Add(onlineWindow + time.Second).Unix())
	if node := list()[0]; node.Online || node.LastSeen == nil || !reflect.DeepEqual(node.Interfaces, want) {
		t.Fatal("offline node lost its last inventory")
	}
	request(http.MethodPost, "/report", a.Token, snapshot, http.StatusNoContent)
	rotated := issue("/nodes/"+a.ID+"/rotate", "", http.StatusOK)
	if rotated.ID != a.ID || rotated.Token == a.Token || list()[0].Online {
		t.Fatal("rotation failed to require a fresh report")
	}
	request(http.MethodPost, "/report", a.Token, snapshot, http.StatusUnauthorized)
	request(http.MethodPost, "/report", rotated.Token, snapshot, http.StatusNoContent)
	request(http.MethodPatch, "/nodes/"+a.ID, adminToken, `{"enabled":false}`, http.StatusNoContent)
	request(http.MethodPost, "/report", rotated.Token, snapshot, http.StatusUnauthorized)
	request(http.MethodPatch, "/nodes/"+a.ID, adminToken, `{"enabled":true}`, http.StatusNoContent)
	if node := list()[0]; !node.Enabled || node.Online || node.LastSeen == nil || !reflect.DeepEqual(node.Interfaces, want) {
		t.Fatal("reenable restored stale report eligibility or lost inventory")
	}
	request(http.MethodPost, "/report", rotated.Token, snapshot, http.StatusNoContent)
	request(http.MethodDelete, "/nodes/"+a.ID, adminToken, "", http.StatusNoContent)
	request(http.MethodPost, "/report", rotated.Token, snapshot, http.StatusUnauthorized)
	if nodes := list(); len(nodes) != 1 || nodes[0].ID != b.ID {
		t.Fatal("deletion changed the wrong node")
	}
}
