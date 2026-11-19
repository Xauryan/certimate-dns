package henet

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func row(id, name, typ, priority, value string) string {
	return fmt.Sprintf(`<tr class="dns_tr" id="%s"><td>51</td><td>%s</td><td>%s</td><td>%s</td><td>300</td><td>%s</td><td>%s</td></tr>`, id, id, name, typ, priority, value)
}

func TestSessionAndScopedWrites(t *testing.T) {
	const sibling = "neighbor.example.test"
	records := row("11", "example.test", "MX", "7", "mail.example.test.") + row("12", sibling, "TXT", "", "&quot;a  b&amp;c&quot;")
	var writes []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/" && r.Method == "GET":
			http.SetCookie(w, &http.Cookie{Name: "preflight", Value: "ready"})
			fmt.Fprint(w, "login")
		case r.URL.Path == "/" && r.Method == "POST":
			c, e := r.Cookie("preflight")
			if e != nil || c.Value != "ready" || r.FormValue("email") != "fixture-user" || r.FormValue("pass") != "fixture-password" {
				t.Error("login form or initial cookie missing")
			}
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "fixture-session"})
			fmt.Fprint(w, `<table id="domains_table"><tr><td><input onclick="delete_dom(this);" name="example.test" value="51"></td></tr></table>`)
		case r.URL.Path == "/index.cgi":
			c, e := r.Cookie("session")
			if e != nil || c.Value != "fixture-session" {
				t.Error("missing login cookie")
			}
			if r.FormValue("hosted_dns_zoneid") != "51" {
				t.Error("unexpected zone")
			}
			if r.Method == "GET" {
				fmt.Fprint(w, "<table>"+records+"</table>")
				return
			}
			writes = append(writes, r.PostForm)
			switch r.FormValue("hosted_dns_editrecord") {
			case "Submit":
				fmt.Fprint(w, `<div id="dns_status">Successfully added new record.</div><table>`+records+row("13", "new.example.test", "TXT", "", "new value")+"</table>")
			case "Update":
				fmt.Fprint(w, `<div id="dns_status">Successfully updated record.</div>`)
			default:
				fmt.Fprint(w, `<div id="dns_status">Successfully removed record.</div>`)
			}
		default:
			t.Errorf("unexpected route %q", r.URL.Path)
		}
	}))
	defer srv.Close()
	p0, err := New(&domain.Access{Config: map[string]any{"username": "fixture-user", "password": "fixture-password"}})
	if err != nil {
		t.Fatal(err)
	}
	p := p0.(*provider)
	p.base = srv.URL + "/"
	ctx := context.Background()
	for _, name := range []string{"", "neighbor.example.test"} {
		pg, err := p.DNSRecords(ctx, "51", 1, name)
		if err != nil {
			t.Fatal(err)
		}
		last := pg.Items[len(pg.Items)-1]
		if last.ID != "12" || last.Content != "a  b&c" {
			t.Fatal(last)
		}
	}
	if _, err = p.PatchDNSRecord(ctx, "51", "99", dns.RecordPatch{TTL: 600, Content: "change"}); err == nil {
		t.Fatal("unlisted record")
	}
	if _, err = p.DeleteDNSRecord(ctx, "52", "11"); err == nil {
		t.Fatal("unlisted zone")
	}
	if _, err = p.CreateDNSRecord(ctx, "51", dns.RecordInput{Name: "other.test", Type: "TXT", TTL: 300, Content: "other"}); err == nil {
		t.Fatal("foreign name")
	}
	if len(writes) != 0 {
		t.Fatal("unexpected write")
	}
	id, err := p.PatchDNSRecord(ctx, "51", "11", dns.RecordPatch{TTL: 900, Content: "other.example.test."})
	if err != nil || id != "11" {
		t.Fatal(id, err)
	}
	if writes[0].Get("Priority") != "7" || writes[0].Get("Name") != "example.test" || writes[0].Get("hosted_dns_recordid") != "11" {
		t.Fatal("lost MX priority or changed sibling")
	}
	id, err = p.CreateDNSRecord(ctx, "51", dns.RecordInput{Type: "TXT", Name: "new.example.test", Content: "new value", TTL: 300})
	if err != nil || id != "13" {
		t.Fatal(id, err)
	}
	id, err = p.DeleteDNSRecord(ctx, "51", "12")
	if err != nil || id != "12" || writes[2].Get("hosted_dns_delconfirm") != "delete" {
		t.Fatal(id, err)
	}
	records += row("bad", "foreign.test", "TXT", "", "hidden")
	if _, err = p.DeleteDNSRecord(ctx, "51", "11"); err == nil || len(writes) != 3 {
		t.Fatal("partial zone write")
	}
}
func TestLoginFailureRedaction(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "Incorrect fixture-password") }))
	defer s.Close()
	p := &provider{s.URL + "/", "fixture-user", "fixture-password", s.Client()}
	_, err := p.Zones(context.Background(), 1)
	if err == nil || strings.Contains(err.Error(), "fixture-password") {
		t.Fatal("login failure must redact the body")
	}
}

func TestSessionUsesAccountTransport(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host != "he.example.test" {
			t.Error("expected absolute proxy request")
		}
		calls++
		fmt.Fprint(w, `<table id="domains_table"></table>`)
	}))
	defer server.Close()
	proxy, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyURL(proxy)
	api, err := New(&domain.Access{Config: map[string]any{"username": "fixture-user", "password": "fixture-password"}, DNSManagementTransport: tr})
	if err != nil {
		t.Fatal(err)
	}
	api.(*provider).base = "http://he.example.test/"
	if _, err = api.Zones(context.Background(), 1); err != nil || calls != 2 {
		t.Fatal(calls, err)
	}
}
