package dnscatalog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/certimate-go/certimate/internal/domain"
	_ "github.com/certimate-go/certimate/migrations"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testCatalog(t *testing.T) core.App {
	t.Helper()
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir(), EncryptionEnv: "DNS_CATALOG_TEST_KEY"})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.ResetBootstrapState() })
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	return app
}
func testAccess(t *testing.T, app core.App, provider, reserve string) *core.Record {
	t.Helper()
	c, err := app.FindCollectionByNameOrId("access")
	if err != nil {
		t.Fatal(err)
	}
	r := core.NewRecord(c)
	r.Set("name", "test")
	r.Set("provider", provider)
	r.Set("reserve", reserve)
	r.Set("config", map[string]string{"value": "synthetic-data"})
	if err := app.Save(r); err != nil {
		t.Fatal(err)
	}
	return r
}

type fakeDNS struct {
	dns.Provider
	pages   [][]dns.Zone
	total   int
	created *dns.Zone
	calls   atomic.Int64
}

func (f *fakeDNS) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	f.calls.Add(1)
	if page < 1 || page > len(f.pages) {
		return nil, errors.New("unexpected page")
	}
	return &dns.DNSPage[dns.Zone]{Items: f.pages[page-1], Info: dns.PageInfo{Page: page, Total: f.total}}, nil
}
func (f *fakeDNS) CreateZone(ctx context.Context, name string) (*dns.Zone, error) {
	f.calls.Add(1)
	return f.created, nil
}
func (f *fakeDNS) resolve(context.Context, string, string, bool) (dns.Provider, error) { return f, nil }

func TestCatalogInventory(t *testing.T) {
	app := testCatalog(t)
	ctx := t.Context()
	for _, provider := range dns.SupportedProviders() {
		a := testAccess(t, app, provider, "")
		enabled, err := IsEnabled(app, a.Id)
		if err != nil || !enabled {
			t.Fatalf("provider %s: %v", provider, err)
		}
	}
	a := testAccess(t, app, "cloudflare", "")
	fake := &fakeDNS{total: 2, pages: [][]dns.Zone{{{ID: "zone1", Name: "One.Example.Test."}}, {{ID: "zone2", Name: "two.example.test"}}}}
	if n, err := ImportZones(ctx, app, a.Id, []string{"zone1"}, fake.resolve); err != nil || n != 1 {
		t.Fatalf("import %d %v", n, err)
	}
	if _, err := LookupZone(app, "cloudflare", a.Id, "zone2"); !errors.Is(err, domain.ErrRecordNotFound) {
		t.Fatal("imported unselected zone")
	}
	z, err := LookupZone(app, "cloudflare", a.Id, "zone1")
	if err != nil || z.Name != "one.example.test" {
		t.Fatalf("lookup %v", err)
	}
	for _, bad := range [][3]string{{"aliyun", a.Id, "zone1"}, {"cloudflare", "unknown", "zone1"}} {
		if _, err := LookupZone(app, bad[0], bad[1], bad[2]); !errors.Is(err, domain.ErrRecordNotFound) {
			t.Fatal("unbound zone")
		}
	}
	if err := UpdateMetadata(app, z.ID, Metadata{Notes: "retain", Tags: []string{"tag", "tag"}, ReminderDays: 30}); err != nil {
		t.Fatal(err)
	}
	if n, err := syncAccount(ctx, app, a.Id, fake.resolve); err != nil || n != 2 {
		t.Fatal(n, err)
	}
	if fake.calls.Load() != 4 {
		t.Fatalf("unexpected pages: %d", fake.calls.Load())
	}
	fake.pages = [][]dns.Zone{{{ID: "zone2", Name: "two.example.test"}}, {}}
	if _, err := syncAccount(ctx, app, a.Id, fake.resolve); err == nil {
		t.Fatal("accepted incomplete inventory")
	}
	if _, err := Lookup(app, z.ID); err != nil {
		t.Fatal(err)
	}
	fake.total = 1
	if _, err := syncAccount(ctx, app, a.Id, fake.resolve); err != nil {
		t.Fatal(err)
	}
	if _, err := Lookup(app, z.ID); !errors.Is(err, domain.ErrRecordNotFound) {
		t.Fatal("absent zone live")
	}
	stale, err := AdminLookup(app, z.ID)
	if err != nil || stale.Notes != "retain" || len(stale.Tags) != 1 {
		t.Fatalf("lost metadata %v", err)
	}
	two, err := LookupZone(app, "cloudflare", a.Id, "zone2")
	if err != nil {
		t.Fatal(err)
	}
	if err := ChangeDomains(ctx, app, BatchChange{IDs: []string{two.ID, "missing"}, Action: "notes", Notes: "rollback"}); err == nil {
		t.Fatal("partial batch")
	}
	two, _ = Lookup(app, two.ID)
	if two.Notes != "" {
		t.Fatal("partial commit")
	}
	fake.created = &dns.Zone{ID: "new", Name: "new.example.test"}
	created, err := CreateZone(ctx, app, a.Id, "new.example.test", func(ctx context.Context, provider, id string, discovery bool) (dns.Provider, error) {
		if discovery {
			t.Fatal("requested read-only discovery credentials to create a zone")
		}
		return fake.resolve(ctx, provider, id, discovery)
	})
	if err != nil || created.ZoneID != "new" {
		t.Fatal(err)
	}
	acc, err := EnsureAccount(app, a.Id)
	if err != nil {
		t.Fatal(err)
	}
	acc.Set("disabled", true)
	if err := app.Save(acc); err != nil {
		t.Fatal(err)
	}
	before := fake.calls.Load()
	if _, err := CreateZone(ctx, app, a.Id, "disabled.example.test", fake.resolve); err == nil || before != fake.calls.Load() {
		t.Fatal("disabled provider mutation")
	}
	if _, err := LookupZone(app, "cloudflare", a.Id, "zone2"); !errors.Is(err, domain.ErrRecordNotFound) {
		t.Fatal("disabled zone live")
	}
}
func TestExpiryRefreshAndDelivery(t *testing.T) {
	app := testCatalog(t)
	ctx := t.Context()
	a := testAccess(t, app, "cloudflare", "")
	channel := testAccess(t, app, "email", "notif")
	f := &fakeDNS{total: 1, pages: [][]dns.Zone{{{ID: "id", Name: "example.test"}}}}
	if _, err := syncAccount(ctx, app, a.Id, f.resolve); err != nil {
		t.Fatal(err)
	}
	z, err := LookupZone(app, "cloudflare", a.Id, "id")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	expiry := now.AddDate(0, 0, 3).Format(time.DateOnly)
	if err := UpdateMetadata(app, z.ID, Metadata{AutoRefresh: true, ReminderEnabled: true, ReminderDays: 5, NotificationID: channel.Id}); err != nil {
		t.Fatal(err)
	}
	if _, err := refreshRegistration(ctx, app, z.ID, func(context.Context, string) (string, string, error) { return "2020-01-01", expiry, nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := refreshRegistration(ctx, app, z.ID, func(context.Context, string) (string, string, error) { return "", "", errors.New("unavailable") }); err == nil {
		t.Fatal("missing failure")
	}
	z, err = Lookup(app, z.ID)
	if err != nil || z.RegistrationStatus != "failed" || z.ExpiresOn != expiry || z.RegisteredOn != "2020-01-01" {
		t.Fatal("lost previous dates")
	}
	attempts := 0
	deliver := func(context.Context, *Domain) error {
		attempts++
		if attempts == 1 {
			return errors.New("delivery failed")
		}
		return nil
	}
	for _, delta := range []time.Duration{0, 0, 2 * time.Hour, 2 * time.Hour} {
		if err := runReminders(ctx, app, now.Add(delta), deliver); err != nil {
			t.Fatal(err)
		}
	}
	if attempts != 2 {
		t.Fatalf("unexpected attempts %d", attempts)
	}
	if err := ScheduleReminders(app); err != nil {
		t.Fatal(err)
	}
}

type testTransport func(*http.Request) (*http.Response, error)

func (f testTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestRegistrationProtocol(t *testing.T) {
	requests := 0
	reg := registry{client: &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		var body string
		switch r.URL.String() {
		case "https://data.iana.org/rdap/dns.json":
			body = `{"services":[[["com"],["https://registry.example.test/rdap/"]]]}`
		case "https://registry.example.test/rdap/domain/example.com":
			body = `{"objectClassName":"domain","ldhName":"EXAMPLE.COM","events":[{"eventAction":"registration","eventDate":"2023-01-01T15:00:00Z"},{"eventAction":"expiration","eventDate":"2030-06-02T01:20:00+08:00"}]}`
		default:
			return nil, fmt.Errorf("unexpected request")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	for range 2 {
		created, expires, err := reg.lookup(t.Context(), "sub.example.com")
		if err != nil || created != "2023-01-01" || expires != "2030-06-01" {
			t.Fatal(created, expires, err)
		}
	}
	if requests != 3 {
		t.Fatal("bootstrap was not cached")
	}
}
func TestCatalogRoutesRequireAdministrator(t *testing.T) {
	app := testCatalog(t)
	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeDNS{}
	Bind(router.Group("/api"), f.resolve)
	mux, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/dns-catalog/accounts", "/api/dns-catalog/domains", "/api/dns-catalog/categories", "/api/collections/dnsZone/records"} {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code == 200 || strings.Contains(w.Body.String(), "synthetic-data") {
			t.Fatal("unprotected " + path)
		}
	}
}

func TestWHOISRegistration(t *testing.T) {
	reg := registry{client: &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://www.iana.org/whois?q=cn" {
			return nil, errors.New("unexpected referral request")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("source: IANA\nwhois:  registry.example.test\n"))}, nil
	})}}
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "registry.example.test:43" {
			return nil, errors.New("unexpected WHOIS endpoint")
		}
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			line, _ := bufio.NewReader(b).ReadString('\n')
			if line == "example.cn\r\n" {
				io.WriteString(b, "Domain Name: EXAMPLE.CN\nRegistration Time: 2020-01-02 08:00:00\nExpiration Time: 2030-01-02 08:00:00\n")
			}
		}()
		return a, nil
	}
	created, expires, err := reg.whois(t.Context(), "example.cn", dial)
	if err != nil || created != "2020-01-02" || expires != "2030-01-02" {
		t.Fatalf("unexpected WHOIS dates: %s %s %v", created, expires, err)
	}
}
