package dnsmcp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/certimate-go/certimate/internal/dnssign"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"software.sslmate.com/src/go-pkcs12"
)

func TestSignedCertificateExportScope(t *testing.T) {
	f := setupInterface(t)
	add := func(collection string, values fields) *core.Record {
		t.Helper()
		col, err := f.app.FindCollectionByNameOrId(collection)
		if err != nil {
			t.Fatal(err)
		}
		rec := core.NewRecord(col)
		rec.Load(values)
		if err := f.app.SaveNoValidate(rec); err != nil {
			t.Fatal(err)
		}
		return rec
	}
	issuer := add("access", fields{"name": "Issuer", "provider": "aliyun", "config": fields{}})
	material := func(names []string) string {
		t.Helper()
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
		if err != nil {
			t.Fatal(err)
		}
		key, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key}))
		rec := add("certificate", fields{"certificate": chain, "privateKey": pemKey, "source": "request", "validityNotBefore": template.NotBefore, "validityNotAfter": template.NotAfter})
		return rec.Id
	}
	order := func(zoneID, domain, certificate string) string {
		t.Helper()
		id := core.GenerateDefaultRandomId()
		_, err := f.app.DB().Insert("dns_cert_orders", dbx.Params{"id": id, "access_id": issuer.Id, "primary_zone_id": zoneID, "provider": "aliyun", "domain": domain, "algorithm": "EC256", "request_json": "{}", "state": "issued", "created": 1, "updated": 1, "certificate_id": certificate}).Execute()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	keyScope := f.keyInput([]string{"cert.order.export", "cert.order.read"}, []string{"api", "mcp"})
	keyScope["global"], keyScope["accounts"] = true, []string{issuer.Id}
	key := f.issue(t, session(t, f.admin), keyScope)
	name := "www.allowed.example"
	valid := order(f.visible.Id, name, material([]string{name}))
	hidden := order(f.hidden.Id, "www.hidden.example", material([]string{"www.hidden.example"}))
	unbound := order("", name, material([]string{name}))
	wrongSAN := order(f.visible.Id, name, material([]string{name, "outside.example"}))
	const exportPath = "/api/cert/order"
	legacy := key.form(time.Now())
	legacy.Set("id", valid)
	rejected := f.postForm(exportPath, legacy)
	expectStatus(t, rejected, http.StatusForbidden)
	if strings.Contains(rejected.Body.String(), "PRIVATE KEY") {
		t.Fatal("legacy signature returned certificate material")
	}
	call := func(id string, want int, allowMaterial bool) {
		t.Helper()
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			t.Fatal(err)
		}
		form := url.Values{"id": {id}, "uid": {key.UID}, "timestamp": {strconv.FormatInt(time.Now().Unix(), 10)}, "sign_version": {"2"}, "nonce": {hex.EncodeToString(nonce[:])}}
		form.Set("sign", dnssign.Sign(exportPath, form, key.APIKey))
		w := f.postForm(exportPath, form)
		expectStatus(t, w, want)
		if !allowMaterial {
			if strings.Contains(w.Body.String(), "PRIVATE KEY") {
				t.Fatal("credential scope leaked certificate key")
			}
			return
		}
		var reply struct {
			Data struct{ CRT, Key, PFX string }
		}
		readJSON(t, w, &reply)
		encoded, err := base64.StdEncoding.DecodeString(reply.Data.PFX)
		if err != nil {
			t.Fatal(err)
		}
		if _, leaf, _, err := pkcs12.DecodeChain(encoded, "123456"); err != nil || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != name {
			t.Fatal("invalid PFX or certificate identity")
		}
		if !strings.Contains(reply.Data.CRT, "CERTIFICATE") || !strings.Contains(reply.Data.Key, "PRIVATE KEY") || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
			t.Fatal("invalid export or cache header")
		}
	}
	call(valid, http.StatusOK, true)
	var legacyID int64
	if err := f.app.DB().NewQuery("SELECT id FROM dns_interface_cert_orders WHERE order_id={:id}").Bind(dbx.Params{"id": valid}).Row(&legacyID); err != nil || legacyID < 1 {
		t.Fatal("legacy certificate ID unavailable")
	}
	call(strconv.FormatInt(legacyID, 10), http.StatusOK, true)
	call(hidden, http.StatusNotFound, false)
	call(unbound, http.StatusNotFound, false)
	call(wrongSAN, http.StatusForbidden, false)
	list := fields{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": fields{"name": "cert_order_query", "arguments": fields{"action": "list", "limit": 1}}}
	w := f.request("POST", "/mcp", key.bearer(), "application/json", testJSON(t, list))
	expectStatus(t, w, http.StatusOK)
	var res struct {
		Result struct {
			IsError           bool
			StructuredContent struct {
				Total int
				Rows  []fields
			}
		}
	}
	readJSON(t, w, &res)
	if res.Result.IsError || res.Result.StructuredContent.Total != 2 || len(res.Result.StructuredContent.Rows) != 1 || strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Fatal("order list count or redaction failed")
	}
}

func TestCertificateAccountMCPRequiresAccountScopeAfterCreation(t *testing.T) {
	f := setupInterface(t)
	admin := session(t, f.admin)
	scope := f.keyInput([]string{"cert.account.add", "cert.account.edit", "cert.account.read", "cert.account.delete"}, []string{"mcp"})
	scope["global"] = true
	creator := f.issue(t, admin, scope)
	call := func(k credential, tool string, args fields, wantError bool) fields {
		t.Helper()
		body := testJSON(t, fields{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": fields{"name": tool, "arguments": args}})
		w := f.request("POST", "/mcp", k.bearer(), "application/json", body)
		expectStatus(t, w, 200)
		var out struct {
			Result struct {
				IsError           bool
				StructuredContent fields
			}
		}
		readJSON(t, w, &out)
		if out.Result.IsError != wantError || out.Result.StructuredContent == nil || strings.Contains(w.Body.String(), "synthetic-account-secret") {
			t.Fatal("unexpected account response, error flag or leaked credential")
		}
		return out.Result.StructuredContent
	}
	call(creator, "cert_account_manage", fields{"action": "add", "deploy": 1, "type": "amh", "name": "Unsupported target", "config": fields{}}, true)
	created := call(creator, "cert_account_manage", fields{"action": "add", "type": "aliyun", "name": "Synthetic issuer", "config": fields{"accessKeyId": "synthetic-account-id", "accessKeySecret": "synthetic-account-secret"}}, false)
	id, ok := created["id"].(string)
	if !ok || id == "" {
		t.Fatal("account id missing")
	}
	edit := fields{"action": "edit", "id": id, "remark": "Maintained for regression test"}
	call(creator, "cert_account_manage", edit, true)
	scope["accounts"] = []string{id}
	scoped := f.issue(t, admin, scope)
	call(scoped, "cert_account_manage", edit, false)
	list := call(scoped, "cert_account_query", fields{"action": "list", "kw": "regression"}, false)
	if list["total"] != float64(1) {
		t.Fatal("account missing from scoped page")
	}
	call(scoped, "cert_account_manage", fields{"action": "edit", "id": id, "deploy": 1, "remark": "wrong role"}, true)
	call(scoped, "cert_account_manage", fields{"action": "del", "id": id}, false)
	list = call(scoped, "cert_account_query", fields{"action": "list"}, false)
	if list["total"] != float64(0) {
		t.Fatal("deleted account still visible")
	}
}
