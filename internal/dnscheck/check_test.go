package dnscheck

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

func TestScopedPropagation(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var queries atomic.Int32
	s := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		queries.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		for _, line := range []string{"target.test. 30 IN TXT \"Case\" \"Sensitive\"", "other.test. 30 IN TXT \"unrelated\"", "target.test. 30 IN A 127.0.0.1"} {
			rr, err := dns.NewRR(line)
			if err != nil {
				panic(err)
			}
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})}
	ready := make(chan struct{})
	s.NotifyStartedFunc = func() { close(ready) }
	go s.ActivateAndServe()
	<-ready
	t.Cleanup(func() { _ = s.Shutdown() })
	addresses := []string{conn.LocalAddr().String()}
	ctx := context.Background()
	if _, err := check(ctx, "target.test", "other.test", "TXT", "unrelated", addresses); !errors.Is(err, ErrInvalid) || queries.Load() != 0 {
		t.Fatalf("out-of-zone query: %v", err)
	}
	for _, tc := range []struct{ value, status string }{{"CaseSensitive", "active"}, {"casesensitive", "mismatch"}} {
		got, err := check(ctx, "target.test", "target.test", "TXT", tc.value, addresses)
		if err != nil || got.Status != tc.status || len(got.Actual) != 1 || got.Actual[0] != "CaseSensitive" {
			t.Fatalf("check %q: %+v, %v", tc.value, got, err)
		}
	}
	if r, err := check(ctx, "target.test", "target.test", "AAAA", "::1", addresses); err != nil || r.Status != "not_found" {
		t.Fatalf("missing type %+v %v", r, err)
	}
}
