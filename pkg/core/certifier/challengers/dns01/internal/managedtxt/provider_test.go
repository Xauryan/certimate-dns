package managedtxt

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	model "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

const (
	rootDomain    = "example.test"
	effectiveName = "txt.delegation.test"
)

func localDNS(t *testing.T) *atomic.Bool {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	changed := new(atomic.Bool)
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		q := request.Question[0]
		switch {
		case q.Qtype == dns.TypeCNAME && q.Name == "_acme-challenge."+rootDomain+".":
			target := effectiveName + "."
			if changed.Load() {
				target = "other.changed.test."
			}
			reply.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: target}}
		case q.Qtype == dns.TypeSOA && (q.Name == "delegation.test." || q.Name == "example.test." || q.Name == "changed.test."):
			reply.Answer = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns." + q.Name, Mbox: "admin." + q.Name, Refresh: 600}}
		}
		_ = w.WriteMsg(reply)
	})
	started := make(chan struct{})
	server := &dns.Server{PacketConn: conn, Handler: handler, NotifyStartedFunc: func() { close(started) }}
	go func() { _ = server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = server.Shutdown() })
	previous := dns01.DefaultClient()
	dns01.SetDefaultClient(dns01.NewClient(&dns01.Options{RecursiveNameservers: []string{conn.LocalAddr().String()}}))
	t.Cleanup(func() { dns01.SetDefaultClient(previous) })
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "false")
	return changed
}

type storedRecord struct {
	zone string
	model.RecordInput
}
type testProvider struct {
	mu                     sync.Mutex
	records                map[string]storedRecord
	next                   int
	failCreate, failDelete bool
}

func (s *testProvider) CreateDNSRecord(ctx context.Context, zone string, in model.RecordInput) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if s.failCreate {
		return "", errors.New("create failed")
	}
	s.next++
	id := strconv.Itoa(s.next)
	s.records[id] = storedRecord{zone, in}
	return id, nil
}

func (s *testProvider) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if s.failDelete {
		return "", errors.New("delete failed")
	}
	rec, ok := s.records[id]
	if !ok || rec.zone != zone {
		return "", errors.New("wrong zone or record ID")
	}
	delete(s.records, id)
	return id, nil
}

func wantValue(keyAuth string, quoted bool) string {
	sum := sha256.Sum256([]byte(keyAuth))
	v := base64.RawURLEncoding.EncodeToString(sum[:])
	if quoted {
		return strconv.Quote(v)
	}
	return v
}

func TestOverlappingTXTAuthorizations(t *testing.T) {
	for _, test := range []struct {
		name                       string
		separateOrders, cloudflare bool
	}{
		{"root and wildcard in one order", false, false},
		{"two concurrent orders", true, false},
		{"two concurrent orders using opaque zone IDs and quoted TXT", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := localDNS(t)
			zone := "delegation.test"
			cfg := Config{TTL: 600, RequestTimeout: time.Second}
			if test.cloudflare {
				zone = "opaque-zone-id"
				cfg.QuoteTXT = true
				cfg.ZoneIDByName = func(_ context.Context, name string) (string, error) {
					if name != "delegation.test" {
						return "", fmt.Errorf("unexpected zone %q", name)
					}
					return zone, nil
				}
			}

			prior := storedRecord{zone, model.RecordInput{Type: "TXT", Name: effectiveName, Content: "pre-existing", TTL: 3600}}
			store := &testProvider{records: map[string]storedRecord{"before": prior}}
			root := New(store, cfg)
			wild := root
			if test.separateOrders {
				wild = New(store, cfg)
			}

			ctx := t.Context()
			var wg sync.WaitGroup
			start := make(chan struct{})
			errs := make(chan error, 2)
			for _, ch := range []struct {
				p            *Provider
				domain, auth string
			}{
				{root, "EXAMPLE.Test.", "synthetic-root"},
				{wild, "*.example.test", "synthetic-wild"},
			} {
				wg.Go(func() { <-start; errs <- ch.p.Present(ctx, ch.domain, "", ch.auth) })
			}
			close(start)
			wg.Wait()
			close(errs)
			for err := range errs {
				require.NoError(t, err)
			}

			require.NoError(t, root.Present(ctx, rootDomain, "", "synthetic-root"))
			require.Len(t, store.records, 3)
			values := map[string]bool{}
			for id, rec := range store.records {
				if id == "before" {
					continue
				}
				require.Equal(t, zone, rec.zone)
				require.Equal(t, "TXT", rec.Type)
				require.Equal(t, effectiveName, rec.Name)
				require.Equal(t, 600, rec.TTL)
				values[rec.Content] = true
			}
			require.Contains(t, values, wantValue("synthetic-root", cfg.QuoteTXT))
			require.Contains(t, values, wantValue("synthetic-wild", cfg.QuoteTXT))

			changed.Store(true)
			store.failDelete = true
			require.Error(t, root.CleanUp(ctx, rootDomain, "", "synthetic-root"))
			require.Len(t, store.records, 3)
			store.failDelete = false
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			require.NoError(t, root.CleanUp(canceled, rootDomain, "", "synthetic-root"))
			require.NoError(t, root.CleanUp(ctx, rootDomain, "", "synthetic-root"))
			require.Len(t, store.records, 2)
			for id, rec := range store.records {
				if id != "before" {
					require.Equal(t, wantValue("synthetic-wild", cfg.QuoteTXT), rec.Content)
				}
			}
			require.NoError(t, wild.CleanUp(ctx, rootDomain, "", "synthetic-wild"))
			require.Equal(t, map[string]storedRecord{"before": prior}, store.records)
		})
	}
}

func TestFailedPresentNeverDeletesExistingTXT(t *testing.T) {
	localDNS(t)
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	existing := storedRecord{rootDomain, model.RecordInput{Type: "TXT", Name: "_acme-challenge." + rootDomain, Content: wantValue("synthetic-duplicate", false)}}
	store := &testProvider{records: map[string]storedRecord{"before": existing}, failCreate: true}
	p := New(store, Config{TTL: 120, RequestTimeout: time.Second})
	ctx := t.Context()
	require.Error(t, p.Present(ctx, rootDomain, "", "synthetic-duplicate"))
	require.NoError(t, p.CleanUp(ctx, rootDomain, "", "synthetic-duplicate"))
	require.Equal(t, map[string]storedRecord{"before": existing}, store.records)
	store.failCreate = false
	require.NoError(t, p.Present(ctx, rootDomain, "", "synthetic-other"))
	require.Equal(t, rootDomain, store.records["1"].zone)
	require.Equal(t, existing.Name, store.records["1"].Name)
}

func TestFinalCleanupAfterOrderCancellation(t *testing.T) {
	localDNS(t)
	prior := storedRecord{"delegation.test", model.RecordInput{Type: "TXT", Content: "before"}}
	store := &testProvider{records: map[string]storedRecord{"before": prior}}
	ctx, cancel := context.WithCancel(t.Context())
	p := New(store, Config{TTL: 600})
	require.NoError(t, p.Present(ctx, rootDomain, "", "synthetic-owned"))
	other := New(store, p.config)
	require.NoError(t, other.Present(ctx, rootDomain, "", "synthetic-other"))

	cancel()
	store.failDelete = true
	require.Error(t, p.CleanUp(ctx, rootDomain, "", "synthetic-owned"))
	err := p.RetryCleanup(ctx)
	require.ErrorContains(t, err, "zone delegation.test, record 1")
	require.NotContains(t, err.Error(), "synthetic-owned")
	require.Len(t, store.records, 3)

	store.failDelete = false
	require.NoError(t, p.RetryCleanup(ctx))
	require.NoError(t, p.RetryCleanup(ctx))
	require.Len(t, store.records, 2)
	require.Equal(t, prior, store.records["before"])
	require.Equal(t, wantValue("synthetic-other", false), store.records["2"].Content)
}
