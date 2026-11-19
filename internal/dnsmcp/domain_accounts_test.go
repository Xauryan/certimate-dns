package dnsmcp

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/domain"
	_ "github.com/certimate-go/certimate/migrations"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestInterfaceAccountInputs(t *testing.T) {
	for _, native := range dns.SupportedProviders() {
		if def := accountDefinitions[legacyAccountType(native)]; def.native != native || len(def.fields) == 0 {
			t.Errorf("missing provider definition for %q", native)
		}
	}
	tests := []struct {
		provider   string
		old, input object
		want       object
		error      bool
	}{
		{"dnspod", object{"secretId": "test-id"}, object{"SecretKey": "test-secret"}, object{"secretId": "test-id", "secretKey": "test-secret"}, false},
		{"dnspod", nil, object{"SecretId": "one", "secretId": "two"}, nil, true},
		{"cloudflare", nil, object{"apikey": "test-token", "auth": "1", "proxy": "0"}, object{"apiToken": "test-token", "dnsManagementProxy": false}, false},
		{"cloudflare", nil, object{"apikey": "test-key", "auth": "0"}, nil, true},
		{"powerdns", nil, object{"ip": "::1", "port": "8081", "apikey": "test-token"}, object{"serverUrl": "http://[::1]:8081", "apiKey": "test-token"}, false},
		{"powerdns", object{"serverUrl": "http://old.test:8081", "apiKey": "test-token"}, object{"ip": "new.test", "port": "8081"}, nil, true},
		{"aliyun", nil, object{"proxy": "1"}, object{"dnsManagementProxy": true}, false},
		{"aliyun", object{"dnsManagementProxy": true}, object{}, object{"dnsManagementProxy": true}, false},
		{"aliyun", nil, object{"dnsManagementProxy": false}, object{"dnsManagementProxy": false}, false},
		{"aliyun", nil, object{"proxy": "0", "dnsManagementProxy": true}, nil, true},
		{"aliyun", nil, object{"proxy": "https://synthetic.invalid"}, nil, true},
		{"aliyun", nil, object{"proxyUrl": "https://synthetic.invalid"}, nil, true},
		{"aliyun", nil, object{"proxyPassword": "synthetic-test"}, nil, true},
		{"aliyun", nil, object{"dnsManagementProxy": "1"}, nil, true},
	}
	for _, tt := range tests {
		got, problem := mergeAccountConfig(tt.provider, tt.old, tt.input)
		if (problem != nil) != tt.error {
			t.Errorf("%s unexpected validation result", tt.provider)
			continue
		}
		if tt.error {
			continue
		}
		a, _ := json.Marshal(got)
		b, _ := json.Marshal(tt.want)
		if string(a) != string(b) {
			t.Errorf("%s credential mapping differs", tt.provider)
		}
	}
}

func TestInterfaceAccountPersistenceAndScope(t *testing.T) {
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.ResetBootstrapState() })
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	superusers, err := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		t.Fatal(err)
	}
	e := &core.RequestEvent{App: app, Auth: core.NewRecord(superusers)}
	e.Auth.SetEmail("account-test@example.test")
	e.Auth.SetPassword("synthetic-admin-password")
	if err := app.Save(e.Auth); err != nil {
		t.Fatal(err)
	}
	e.Set(keyUID, "57")
	e.Set(keyScopeJSON, "{}")
	if _, err := app.DB().NewQuery("INSERT INTO dns_interface_keys (uid,owner_collection,owner,label,scope) VALUES ('57','_superusers',{:id},'test','{}')").Bind(dbx.Params{"id": e.Auth.Id}).Execute(); err != nil {
		t.Fatal(err)
	}
	e.Request = httptest.NewRequest("POST", "/mcp", nil)
	noProbe := func(context.Context, *domain.Access) *opError {
		t.Fatal("attempted delegated network probe against operator-defined endpoint")
		return upstream
	}
	for _, legacy := range []string{"powerdns", "technitium", "dnsmgr", "goedge"} {
		provider := accountDefinitions[legacy].native
		candidate := object{"serverUrl": "https://synthetic.invalid/", "apiKey": "synthetic-key"}
		cfg := object{}
		for _, key := range accountDefinitions[legacy].fields {
			value := any("synthetic-value")
			if key == "serverUrl" {
				value = candidate["serverUrl"]
			}
			cfg[key] = value
		}
		if _, problem := saveInterfaceAccount(e, "add", object{"type": legacy, "config": cfg}, noProbe); problem != denied {
			t.Fatalf("%s external setup should be denied", legacy)
		}
		c, err := app.FindCollectionByNameOrId("access")
		if err != nil {
			t.Fatal(err)
		}
		original := core.NewRecord(c)
		original.Set("name", "synthetic local "+legacy)
		original.Set("provider", provider)
		original.Set("config", cfg)
		if err := app.Save(original); err != nil {
			t.Fatal(err)
		}
		if _, problem := saveInterfaceAccount(e, "edit", object{"id": original.Id, "remark": "changed"}, noProbe); problem != denied {
			t.Fatalf("%s delegated edit of operator endpoint should be denied", legacy)
		}
	}
	if delegatedAccountProbeAllowed("aws", object{"authMethod": "imds"}) || delegatedAccountProbeAllowed("future-driver", object{}) {
		t.Fatal("delegated validation enabled for a non-static destination")
	}
	const syntheticSecret = "synthetic-list-redaction-test"
	add := func(name string, probe checkAccount) (string, *opError) {
		out, problem := saveInterfaceAccount(e, "add", object{"type": "dnspod", "name": name, "config": object{"SecretId": "test-id", "SecretKey": syntheticSecret}, "remark": "catalog note"}, probe)
		if problem != nil {
			return "", problem
		}
		return out["id"].(string), nil
	}
	good := func(_ context.Context, a *domain.Access) *opError {
		if a.Provider != "tencentcloud" || a.Config["secretKey"] != syntheticSecret {
			t.Fatal("incorrect native credential")
		}
		return nil
	}
	id, problem := add("visible", good)
	if problem != nil {
		t.Fatal(problem)
	}
	other, problem := add("hidden", good)
	if problem != nil {
		t.Fatal(problem)
	}
	if _, problem := add("failed", func(context.Context, *domain.Access) *opError { return upstream }); problem != upstream {
		t.Fatal("expected provider validation failure")
	}
	all, problem := interfaceAccountList(e, object{}, scope{Accounts: []string{id, other}})
	if problem != nil || all["total"] != 2 {
		t.Fatalf("unexpected account inventory %v", problem)
	}
	unbound, problem := interfaceAccountList(e, object{}, scope{Global: true})
	if problem != nil || unbound["total"] != 0 {
		t.Fatal("global creation scope disclosed unrelated accounts")
	}
	only, problem := interfaceAccountList(e, object{"limit": "1"}, scope{Accounts: []string{id}})
	if problem != nil || only["total"] != 1 {
		t.Fatalf("unexpected scoped count: %v", problem)
	}
	b, _ := json.Marshal(only)
	if strings.Contains(string(b), syntheticSecret) || strings.Contains(string(b), other) || !strings.Contains(string(b), "catalog note") {
		t.Fatal("unsafe or incomplete account projection")
	}
	_, problem = (service{}).domainAccount(e, "dns_account_manage", "del", object{"id": other}, scope{Accounts: []string{id}})
	if problem != denied {
		t.Fatal("key may not delete unrelated accounts")
	}
	stale := func(_ context.Context, a *domain.Access) *opError {
		r, err := app.FindRecordById("access", id)
		if err != nil {
			t.Fatal(err)
		}
		r.Set("name", "concurrent edit")
		if err := app.Save(r); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	_, problem = saveInterfaceAccount(e, "edit", object{"id": id, "name": "lost update"}, stale)
	if problem != accountConflict {
		t.Fatal("concurrent edit overwritten", problem)
	}
	if _, problem = removeInterfaceAccount(e, id); problem != nil {
		t.Fatal(problem)
	}
	only, problem = interfaceAccountList(e, object{}, scope{Accounts: []string{id}})
	if problem != nil || only["total"] != 0 {
		t.Fatal("soft-deleted account visible")
	}
	types, problem := interfaceProviderTypes(object{"category": "dns"})
	if problem != nil {
		t.Fatal(problem)
	}
	var ids []string
	for _, row := range types["data"].([]object) {
		ids = append(ids, row["type"].(string))
	}
	if len(ids) != len(dns.SupportedProviders()) || !slices.IsSorted(ids) {
		t.Fatal("incorrect provider list")
	}
}
