package dnsproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDirectAndForwardProxyAreIndependent(t *testing.T) {
	p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host != "dns.test" || r.Header.Get("Proxy-Authorization") != "Basic dGVzdDprZXk=" {
			t.Errorf("wrong route or missing proxy credentials")
		}
		w.WriteHeader(204)
	}))
	defer p.Close()
	u, _ := url.Parse(p.URL)
	u.User = url.UserPassword("test", "key")
	tr, err := NewTransport(u)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr}).Get("http://dns.test/zones")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	local, err := NewTransport(nil)
	if err != nil || local.Proxy != nil || tr.Proxy == nil {
		t.Fatal("direct and forced proxy routes should be independent")
	}
}

func TestHTTPSProxyIsVerifiedWhenOriginHasPrivateCertificate(t *testing.T) {
	var hits atomic.Int32
	p := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(502) }))
	p.Config.ErrorLog = log.New(io.Discard, "", 0)
	p.StartTLS()
	defer p.Close()
	u, _ := url.Parse(p.URL)
	tr, err := NewTransport(u)
	if err != nil {
		t.Fatal(err)
	}
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // explicit origin setting
	if _, err = (&http.Client{Transport: tr}).Get("https://dns.test/"); err == nil || hits.Load() != 0 {
		t.Fatal("untrusted proxy received a request")
	}
}

func TestSOCKSProxyAddressAndCredentials(t *testing.T) {
	tests := []struct{ scheme, host string }{{"socks4", "127.0.0.1"}, {"socks5", "127.0.0.1"}, {"socks5h", "only-at-proxy.test"}}
	for _, tt := range tests {
		t.Run(tt.scheme, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := ln.Accept()
				if err != nil {
					t.Error(err)
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(c)
				read := func(n int) []byte {
					b := make([]byte, n)
					if _, err := io.ReadFull(reader, b); err != nil {
						t.Error(err)
					}
					return b
				}
				if tt.scheme == "socks4" {
					b := read(8)
					user, err := reader.ReadString(0)
					if err != nil || b[0] != 4 || b[1] != 1 || b[3] != 80 || string(b[4:]) != "\x7f\x00\x00\x01" || user != "tester\x00" {
						t.Error("wrong SOCKS4 handshake")
					}
					c.Write([]byte{0, 90, 0, 0, 0, 0, 0, 0})
				} else {
					greeting := read(2)
					if greeting[0] != 5 {
						t.Error("wrong SOCKS version")
					}
					read(int(greeting[1]))
					c.Write([]byte{5, 2})
					auth := read(2)
					name := read(int(auth[1]))
					length := read(1)
					password := read(int(length[0]))
					if auth[0] != 1 || string(name) != "tester" || string(password) != "secret" {
						t.Error("SOCKS5 auth mismatch")
					}
					c.Write([]byte{1, 0})
					connect := read(4)
					if tt.scheme == "socks5" {
						if connect[3] != 1 || string(read(4)) != "\x7f\x00\x00\x01" {
							t.Error("expected locally resolved IP address")
						}
					} else {
						if connect[3] != 3 {
							t.Error("expected proxy DNS lookup")
						}
						n := read(1)
						if string(read(int(n[0]))) != tt.host {
							t.Error("wrong hostname")
						}
					}
					read(2)
					c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				}
				req, err := http.ReadRequest(reader)
				if err != nil || req.Host != tt.host {
					t.Error("origin request did not arrive over established tunnel")
					return
				}
				req.Body.Close()
				io.WriteString(c, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
			}()
			u := &url.URL{Scheme: tt.scheme, Host: ln.Addr().String(), User: url.UserPassword("tester", "secret")}
			tr, err := NewTransport(u)
			if err != nil {
				t.Fatal(err)
			}
			defer tr.CloseIdleConnections()
			resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("http://" + tt.host + "/zone")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			<-done
		})
	}
}

func TestInvalidOrUnavailableProxyHasNoFallback(t *testing.T) {
	for _, s := range []string{"http://bad.test", "http://bad.test:0", "ftp://bad.test:21", "http://bad.test:20/path", "http://bad.test:20?q=1"} {
		u, _ := url.Parse(s)
		if _, err := NewTransport(u); err == nil {
			t.Errorf("accepted invalid endpoint %s", s)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	u := &url.URL{Scheme: "socks5h", Host: addr, User: url.UserPassword("tester", "secret")}
	tr, _ := NewTransport(u)
	_, err = tr.DialContext(context.Background(), "tcp", "example.test:80")
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("unexpected fallback or credential disclosure")
	}
}
