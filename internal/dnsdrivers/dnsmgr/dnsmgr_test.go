package dnsmgr

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestSignedZoneOperations(t *testing.T) {
	ctx := context.Background()
	rows := `[]`
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.URL.RawQuery != "" || r.Form.Get("sign") != fmt.Sprintf("%x", md5.Sum([]byte("2"+r.Form.Get("timestamp")+"synthetic-key"))) {
			t.Error("signature mismatch")
		}
		switch r.URL.Path {
		case "/api/domain/1":
			fmt.Fprint(w, `{"code":0,"data":{"id":1,"name":"example.test","recordLine":[{"id":"edge","name":"Edge","parent":null}],"minTTL":60}}`)
		case "/api/record/data/1":
			fmt.Fprint(w, rows)
		case "/api/record/add/1":
			if r.Form.Get("line") != "edge" || r.Form.Get("remark") != "saved" || r.Form.Get("weight") != "8" {
				t.Error("missing create options")
			}
			writes++
			rows = `[{"RecordId":"abc","Domain":"example.test","Name":"www","Type":"TXT","TTL":60,"Value":"text","Line":"edge","Weight":"8","Remark":"saved","Status":"1"}]`
			fmt.Fprint(w, `{"code":0}`)
		case "/api/record/update/1":
			if r.Form.Get("recordid") != "abc" || r.Form.Get("name") != "www" || r.Form.Get("weight") != "8" || r.Form.Get("remark") != "saved" {
				t.Error("update metadata changed")
			}
			writes++
			fmt.Fprint(w, `{"code":0}`)
		default:
			w.WriteHeader(403)
			fmt.Fprint(w, "synthetic-key")
		}
	}))
	defer server.Close()
	acc := &domain.Access{Config: map[string]any{"uid": "2", "apiKey": "synthetic-key", "serverUrl": server.URL}}
	api, err := New(acc)
	if err != nil {
		t.Fatal(err)
	}
	p := api.(*provider)
	w := 8
	in := dns.RecordInput{Name: "www.example.test", Type: "TXT", Content: "text", TTL: 60, Line: "edge", Weight: &w, Description: "saved"}
	id, err := p.CreateDNSRecord(ctx, "1", in)
	if err != nil || id != "abc" {
		t.Fatalf("%s %v", id, err)
	}
	if _, err = p.CreateDNSRecord(ctx, "1", in); err == nil {
		t.Fatal("claimed existing record")
	}
	if _, err = p.PatchDNSRecord(ctx, "1", id, dns.RecordPatch{TTL: 120, Content: "next"}); err != nil {
		t.Fatal(err)
	}
	info, err := p.ZoneDetails(ctx, "1")
	if err != nil || info.MinTTL != 60 || len(info.Lines) != 1 {
		t.Fatal(info, err)
	}
	for _, bad := range []string{`{"total":2,"rows":[{"RecordId":"abc","Domain":"example.test","Name":"www","Type":"TXT","TTL":60}]}`, `[{"RecordId":"abc","Domain":"foreign.test","Name":"www","Type":"TXT","TTL":60}]`} {
		rows = bad
		if _, err = p.DeleteDNSRecord(ctx, "1", id); err == nil {
			t.Fatal("accepted partial or foreign record")
		}
	}
	if _, err := p.DNSRecords(ctx, "4", 1, ""); err == nil || strings.Contains(err.Error(), "synthetic-key") {
		t.Fatal("unredacted provider error")
	}
	if writes != 2 {
		t.Fatal(writes)
	}
}

func TestSignatureModesThroughLocalAPI(t *testing.T) {
	for _, mode := range []string{"", "legacy", "v2"} {
		t.Run("mode-"+mode, func(t *testing.T) {
			nonces := map[string]bool{}
			hits := 0
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits++
				if r.URL.Path != "/api/record/add/7" || r.URL.RawQuery != "" {
					t.Error("invalid outgoing route")
				}
				raw, _ := io.ReadAll(r.Body)
				if strings.Contains(string(raw), "synthetic-secret") {
					t.Error("secret in outgoing form")
				}
				form, err := url.ParseQuery(string(raw))
				if err != nil {
					t.Error(err)
					return
				}
				sig := form.Get("sign")
				if mode == "v2" {
					nonce := form.Get("nonce")
					decoded, err := hex.DecodeString(nonce)
					if err != nil || len(decoded) != 16 || strings.ToLower(nonce) != nonce || nonces[nonce] || form.Get("sign_version") != "2" {
						t.Error("invalid or reused nonce")
					}
					nonces[nonce] = true
					form.Del("sign")
					mac := hmac.New(sha256.New, []byte("synthetic-secret"))
					fmt.Fprint(mac, "DNSMgr-v2\nPOST\n"+r.URL.EscapedPath()+"\n"+form.Encode())
					if sig != hex.EncodeToString(mac.Sum(nil)) {
						t.Error("request signature mismatch")
					}
				} else {
					if form.Has("sign_version") || form.Has("nonce") {
						t.Error("legacy fields changed")
					}
					if sig != fmt.Sprintf("%x", md5.Sum([]byte("12"+form.Get("timestamp")+"synthetic-secret"))) {
						t.Error("legacy signature mismatch")
					}
				}
				if hits == 2 {
					w.WriteHeader(403)
					fmt.Fprint(w, "synthetic-secret "+sig)
					return
				}
				fmt.Fprint(w, `{"code":0}`)
			})
			srv := httptest.NewServer(http.StripPrefix("/reverse", handler))
			defer srv.Close()
			a := &domain.Access{Config: map[string]any{"uid": "12", "apiKey": "synthetic-secret", "serverUrl": srv.URL + "/reverse"}}
			if mode != "" {
				a.Config["signatureMode"] = mode
			}
			api, err := New(a)
			if err != nil {
				t.Fatal(err)
			}
			p := api.(*provider)
			form := url.Values{"value": {"escaped + ü & =: /"}}
			if err = p.post(context.Background(), "record/add/7", form, nil); err != nil {
				t.Fatal(err)
			}
			if err = p.post(context.Background(), "record/add/7", form, nil); err == nil || strings.Contains(err.Error(), "synthetic-secret") || strings.Contains(err.Error(), form.Get("sign")) {
				t.Fatal("provider rejected signature without a redacted error")
			}
			if hits != 2 {
				t.Fatalf("unexpected fallback requests: %d", hits)
			}
		})
	}
	for _, mode := range []any{"V2", "other", 2, false} {
		if _, err := New(&domain.Access{Config: map[string]any{"uid": "12", "apiKey": "synthetic-secret", "serverUrl": "https://example.test", "signatureMode": mode}}); err == nil {
			t.Fatal("invalid signature mode accepted")
		}
	}
}
