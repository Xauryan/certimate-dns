package cloudflare

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type dnsTransportFunc func(*http.Request) (*http.Response, error)

func (f dnsTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDNSTransportAndGuardedRecordWrites(t *testing.T) {
	const zone = "01234567890abcdef01234567890abcd"
	const id = "01234567890abcdef01234567890abce"
	redirect := false
	requests := 0
	transport := dnsTransportFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.Method != "GET" || r.URL.Host != "api.cloudflare.com" || r.Header.Get("Authorization") != "Bearer sample-token" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Host)
		}
		if _, ok := r.Context().Deadline(); !ok {
			t.Fatal("missing timeout on custom transport")
		}
		res := &http.Response{StatusCode: 200, Header: make(http.Header), Request: r}
		res.Header.Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/client/v4/zones":
			if redirect {
				res.StatusCode = 302
				res.Header.Set("Location", "https://redirect.test/")
			}
			res.Body = io.NopCloser(strings.NewReader(`{"success":true,"result":[],"result_info":{"page":1,"total_count":0}}`))
		case "/client/v4/zones/" + zone + "/dns_records/" + id:
			res.Body = io.NopCloser(strings.NewReader(`{"success":true,"result":{"id":"` + id + `","type":"TXT","name":"example.test","locked":true}}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		return res, nil
	})
	c, err := NewClient(WithApiToken("sample-token"), WithDNSTransport(transport))
	if err != nil {
		t.Fatal(err)
	}
	c.SetTimeout(time.Second)
	if _, err := c.Zones(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DeleteDNSRecord(t.Context(), zone, id); err == nil || requests != 2 {
		t.Fatal("protected record was modified or skipped the account transport")
	}
	redirect = true
	if _, err := c.Zones(t.Context(), 1); err == nil || requests != 3 {
		t.Fatal("followed redirect or reported success")
	}
}
