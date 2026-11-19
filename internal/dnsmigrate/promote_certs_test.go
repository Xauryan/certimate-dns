package dnsmigrate

import (
	"testing"

	"github.com/pocketbase/dbx"
	_ "modernc.org/sqlite"
)

func TestCertificatePromotions(t *testing.T) {
	db, err := dbx.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const schema = `
CREATE TABLE access(id,deleted,provider,reserve);
CREATE TABLE dns_cert_account_meta(access_id,legacy_type,deploy);
CREATE TABLE dns_cert_orders(id,access_id,provider,domain,state,certificate_id);
CREATE TABLE certificate(id,source,subjectName,subjectAltNames,deleted,workflowRef,workflowRunRef,workflowNodeId);
CREATE TABLE workflow(id,hasContent,graphContent);
CREATE TABLE workflow_run(id,workflowRef,graph);
CREATE TABLE dns_cert_deploy(id,order_id,access_id,workflow_id,node_id,active);
CREATE TABLE dnsZone(id,name);
CREATE TABLE dns_cert_cnames(id,target_zone_id,target_name,source_zone_id,source_name,rr,domain);
INSERT INTO access VALUES('issuer','','aliyun',''),('deployer','','1panel',''),('acme','','letsencrypt','ca');
INSERT INTO dns_cert_account_meta VALUES('deployer','opanel',1);
INSERT INTO dns_cert_orders VALUES('order1','issuer','aliyun','api.example.test','pending','');
INSERT INTO certificate VALUES('uploaded','upload','','cdn.example.test;*.example.test','','','',''),
	('issued','request','acme.example.test','acme.example.test','','workflow','run','apply');
INSERT INTO workflow VALUES('workflow',1,'{"nodes":[{"id":"ship","type":"bizDeploy","data":{"config":{"provider":"1panel-site","providerAccessId":"deployer"}}}]}');
INSERT INTO workflow_run VALUES('run','workflow','{"nodes":[{"id":"block","blocks":[{"id":"apply","type":"bizApply","data":{"config":{"caProviderAccessId":"acme"}}}]}]}');
INSERT INTO dns_cert_deploy VALUES('deploy','order1','deployer','workflow','ship',0);
INSERT INTO dnsZone VALUES('source','example.test'),('dest','delegate.example.test');
INSERT INTO dns_cert_cnames VALUES('cname','dest','delegate.example.test','source','example.test','verify','app.example.test');
`
	if _, err := db.NewQuery(schema).Execute(); err != nil {
		t.Fatal(err)
	}
	m := &Manifest{Related: []Related{
		{Kind: "cert_account", ID: 1, Provider: "aliyun"}, {Kind: "cert_account", ID: 2, State: 1, Provider: "opanel"}, {Kind: "cert_account", ID: 3, Provider: "letsencrypt"},
		{Kind: "cert_order", ID: 1, ParentID: 1}, {Kind: "cert_domain", ID: 1, ParentID: 1, Domain: "api.example.test"},
		{Kind: "cert_order", ID: 2}, {Kind: "cert_domain", ID: 2, ParentID: 2, Domain: "*.example.test"}, {Kind: "cert_domain", ID: 3, ParentID: 2, Domain: "cdn.example.test"},
		{Kind: "cert_order", ID: 3, ParentID: 3}, {Kind: "cert_domain", ID: 4, ParentID: 3, Domain: "acme.example.test"},
		{Kind: "cert_deploy", ID: 1, ParentID: 2, OrderID: 1}, {Kind: "cert_cname", ID: 1, ParentID: 9, Domain: "app.example.test", RR: "verify"},
	}}
	p := &planner{ctx: t.Context(), db: db, manifest: m}
	p.report.Items = append(p.report.Items, Item{Kind: "domain", Legacy: 9, AccountID: "dns-account", Target: "dest"})
	for _, row := range m.Related {
		p.report.Items = append(p.report.Items, Item{Kind: row.Kind, Legacy: row.ID, details: row})
	}
	targets := []string{"issuer", "deployer", "acme", "order1", "order1", "uploaded", "uploaded", "uploaded", "issued", "issued", "deploy", "cname"}
	for idx, r := range m.Related {
		b := Promotion{Kind: r.Kind, LegacyID: r.ID, TargetID: targets[idx], Confirm: true}
		if r.Kind == "cert_order" && r.ID == 3 {
			b.Role = "certificate"
		}
		p.bindings.Promotions = append(p.bindings.Promotions, b)
	}
	check := func(idx int, conflict bool) {
		t.Helper()
		b := p.bindings.Promotions[idx]
		source, _ := p.sourceItem(b.Kind, b.LegacyID)
		w, err := p.planCertPromotion(b, source, false)
		if err != nil || (w.Conflict != "") != conflict || w.Apply != nil {
			t.Fatalf("promotion %s/%d: %q err=%v", b.Kind, b.LegacyID, w.Conflict, err)
		}
	}
	for i := range p.bindings.Promotions {
		check(i, false)
	}
	updates := []struct {
		sql string
		idx int
	}{
		{"UPDATE access SET provider='ali-synthetic' WHERE id='issuer'", 0},
		{"UPDATE dns_cert_account_meta SET deploy=0", 1},
		{"UPDATE dns_cert_orders SET access_id='acme'", 3},
		{"UPDATE certificate SET subjectAltNames='cdn.example.test' WHERE id='uploaded'", 5},
		{"UPDATE workflow_run SET graph='{\"nodes\":[{\"id\":\"apply\",\"type\":\"bizApply\",\"data\":{\"config\":{\"caProviderAccessId\":\"different\"}}}]}'", 8},
		{"UPDATE workflow SET graphContent='{\"nodes\":[]}'", 10},
		{"UPDATE dns_cert_cnames SET rr='unexpected'", 11},
	}
	for _, tc := range updates {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.NewQuery(tc.sql).Execute(); err != nil {
			t.Fatal(err)
		}
		p.db = tx
		check(tc.idx, true)
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
		p.db = db
	}
}

func TestCertificateAccountWindowsBaotaRequiresNativeWindowsProvider(t *testing.T) {
	db, err := dbx.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const schema = `
CREATE TABLE access(id,deleted,provider,reserve);
CREATE TABLE dns_cert_account_meta(access_id,legacy_type,deploy);
INSERT INTO access VALUES('linux','','baotapanel',''),('windows','','baotapanelgo','');
INSERT INTO dns_cert_account_meta VALUES('linux','btwin',1),('windows','btwin',1);`
	if _, err := db.NewQuery(schema).Execute(); err != nil {
		t.Fatal(err)
	}
	p := &planner{ctx: t.Context(), db: db}
	source := Related{Kind: "cert_account", ID: 1, Provider: "btwin", State: 1}
	for _, id := range []string{"linux", "windows"} {
		got, err := p.verifyCertificateAccount(id, source)
		if err != nil || (got.Conflict == "") != (id == "windows") {
			t.Fatalf("unexpected Windows account mapping for %s: %q, %v", id, got.Conflict, err)
		}
	}
}
