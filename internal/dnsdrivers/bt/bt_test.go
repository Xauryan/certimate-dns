package bt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestBaotaWireContract(t *testing.T) {
	api, err := New(&domain.Access{Config: map[string]any{"accountId": "test-account", "accessKey": "synthetic-access", "secretKey": "synthetic-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	p := api.(*provider)
	ctx := context.Background()
	pre := `{"domain_id":75,"domain_type":2,"record":"www","record_id":7,"type":"A","value":"127.0.0.1","TTL":600,"viewID":3,"MX":8,"remark":"keep","state":1}`
	next := strings.Replace(pre, `"record_id":7`, `"record_id":9`, 1)
	count := 1
	rows := pre
	updates := 0
	creates := 0
	p.http.Transport = transport(func(r *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(r.Body)
		var q map[string]any
		json.Unmarshal(raw, &q)
		sig := hmac.New(sha256.New, []byte("synthetic-secret"))
		fmt.Fprintf(sig, "test-account\n%s\nPOST\n%s\n%s", r.Header.Get("X-Timestamp"), r.URL.Path, raw)
		if r.Header.Get("X-Access-Key") != "synthetic-access" || hex.EncodeToString(sig.Sum(nil)) != r.Header.Get("X-Signature") {
			t.Error("incorrect HMAC")
		}
		var data string
		switch strings.TrimPrefix(r.URL.Path, "/api/v1/dns") {
		case "/manage/check_domain_status":
			data = `{"domain_id":75,"domain_type":2,"full_domain":"example.test"}`
		case "/record/list":
			if q["domain_id"] != float64(75) || q["domain_type"] != float64(2) {
				t.Error("list scope")
			}
			data = fmt.Sprintf(`{"count":%d,"data":[%s]}`, count, rows)
		case "/record/create":
			creates++
			rows += "," + next
			count++
			data = "{}"
			if q["view_id"] != float64(3) || q["mx"] != float64(8) || q["remark"] != "keep" {
				t.Error("lost create attributes")
			}
		case "/record/update":
			updates++
			if len(q) != 5 || q["record_id"] != float64(9) || q["ttl"] != float64(300) || q["value"] != "127.0.0.2" {
				t.Error("partial update replaced metadata")
			}
			data = "{}"
		default:
			return &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader("synthetic-secret"))}, nil
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"code":0,"data":` + data + `}`))}, nil
	})
	weight := 8
	in := dns.RecordInput{Name: "www.example.test", Type: "A", TTL: 600, Content: "127.0.0.1", Line: "3", Weight: &weight, Description: "keep"}
	id, err := p.CreateDNSRecord(ctx, "75|2", in)
	if err != nil || id != "9" {
		t.Fatalf("create %s: %v", id, err)
	}
	if _, err := p.PatchDNSRecord(ctx, "75|2", "9", dns.RecordPatch{TTL: 300, Content: "127.0.0.2"}); err != nil {
		t.Fatal(err)
	}
	count = 3
	if _, err := p.PatchDNSRecord(ctx, "75|2", "9", dns.RecordPatch{TTL: 300, Content: "127.0.0.2"}); err == nil {
		t.Fatal("partial listing permitted write")
	}
	count = 1
	rows = strings.Replace(pre, `"domain_id":75`, `"domain_id":76`, 1)
	if _, err := p.DeleteDNSRecord(ctx, "75|2", "7"); err == nil {
		t.Fatal("wrong zone accepted")
	}
	if _, err := p.Zones(ctx, 1); err == nil || strings.Contains(err.Error(), "synthetic") {
		t.Fatal("provider error leaked")
	}
	if creates != 1 || updates != 1 {
		t.Fatal(creates, updates)
	}
}

func TestBaotaUsesAccountTransport(t *testing.T) {
	proxyURL, _ := url.Parse("http://localhost:3128")
	route := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	api, err := New(&domain.Access{Config: map[string]any{"accountId": "synthetic-account", "accessKey": "synthetic-access", "secretKey": "synthetic-secret"}, DNSManagementTransport: route})
	if err != nil {
		t.Fatal(err)
	}
	if api.(*provider).http.Transport != route {
		t.Fatal("account transport discarded")
	}
}
