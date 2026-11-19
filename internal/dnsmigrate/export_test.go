package dnsmigrate

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// All source SQL projections run against the same column names as schema 1049.
// Omitted payloads carry synthetic sentinels to detect accidental export.
func TestExportInventory(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const schema = `
CREATE TABLE old_config(key,value);
CREATE TABLE old_account(id,type,config);
CREATE TABLE old_domain(id,aid,cid,name,thirdid,expiretime,is_notice,regtime,is_hide,is_sso);
CREATE TABLE old_sctask(id,did,rr,recordid,active,type,cycle,switchtype,switchdate,switchtime,value,line);
CREATE TABLE old_dmtask(id,did,rr,recordid,active,type,main_value,backup_value,checktype,checkurl,tcpport,frequency,cycle,timeout,proxy,cdn);
CREATE TABLE old_optimizeip(id,did,rr,active,type,ip_type,cdn_type,recordnum,ttl);
CREATE TABLE old_domain_alias(id,did,name);
CREATE TABLE old_domain_category(id,sort,name);
CREATE TABLE old_user(id,status,password,apikey,totp_secret);
CREATE TABLE old_permission(id,uid,domain,sub);
CREATE TABLE old_cert_account(id,deploy,type,config);
CREATE TABLE old_cert_order(id,aid,status,privatekey);
CREATE TABLE old_cert_domain(id,oid,domain,sort);
CREATE TABLE old_cert_deploy(id,aid,oid,active,config);
CREATE TABLE old_cert_cname(id,did,domain,rr,status);
CREATE TABLE old_log(id,data);
CREATE TABLE old_dmlog(id,errmsg);
INSERT INTO old_config VALUES ('version','1049'),('smtp_pass','synthetic-secret-config');
INSERT INTO old_account VALUES (3,'aws','synthetic-secret-credential');
INSERT INTO old_domain VALUES (7,3,2,'EXAMPLE.test.','Z123',NULL,1,NULL,0,1);
INSERT INTO old_sctask VALUES (1,7,'www','synthetic-secret-composite-record-content',1,1,0,0,NULL,'23:59','edge.example.test',NULL);
INSERT INTO old_dmtask VALUES (1,7,'www','2',0,1,'example.test',NULL,2,'https://example.test/synthetic-secret-url',NULL,10,2,2,0,0);
INSERT INTO old_optimizeip VALUES (1,7,'edge',1,0,'v4,v6',1,2,600);
INSERT INTO old_domain_category VALUES (2,1,'申领域名');
INSERT INTO old_domain_alias VALUES (1,7,'alias.example.test');
INSERT INTO old_user VALUES (1000,1,'synthetic-secret-hash','synthetic-secret-key','synthetic-secret-totp');
INSERT INTO old_permission VALUES (1,1000,'example.test',NULL);
INSERT INTO old_cert_account VALUES (1,1,'bt','synthetic-secret-config');
INSERT INTO old_cert_order VALUES (2,0,1,'synthetic-secret-key');
INSERT INTO old_cert_domain VALUES (3,2,'*.example.test',1);
INSERT INTO old_cert_deploy VALUES (4,1,2,1,'synthetic-secret-config');
INSERT INTO old_cert_cname VALUES (5,7,'example.test','_acme-challenge',0);
INSERT INTO old_log VALUES (1,'synthetic-secret-audit');
INSERT INTO old_dmlog VALUES (1,'synthetic-secret-error');`
	if _, err = db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	m, err := Export(t.Context(), db, "fixture", "old_", "Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Related) != 9 || len(m.Tasks) != 3 || len(m.Zones) != 1 || m.Zones[0].Name != "example.test" || m.Zones[0].CategoryID != 2 || m.Tasks[0].Record != "" || !m.Tasks[1].Monitor.HasURL || *m.History != (HistoryCounts{2, 1, 1}) {
		t.Fatal("incomplete or incorrectly related inventory")
	}
	b, err := json.Marshal(m)
	if err != nil || strings.Contains(string(b), "synthetic-secret") {
		t.Fatal("manifest contains excluded data")
	}
	if _, err = db.Exec("DELETE FROM old_user"); err != nil {
		t.Fatal(err)
	}
	if _, err = Export(t.Context(), db, "fixture", "old_", "UTC"); err == nil {
		t.Fatal("export accepted an orphaned permission")
	}
	if _, err = Export(t.Context(), db, "fixture", "old_;", "UTC"); err == nil {
		t.Fatal("invalid prefix accepted")
	}
}

func TestDecodeRejectsExtraFields(t *testing.T) {
	for _, raw := range []string{`{"credential":"synthetic"}`, `{} {}`} {
		var m Manifest
		if Decode(strings.NewReader(raw), &m) == nil {
			t.Fatal("accepted unknown or trailing data")
		}
	}
}
