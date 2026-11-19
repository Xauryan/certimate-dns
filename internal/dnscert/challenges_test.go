package dnscert

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/certimate-go/certimate/internal/dnscatalog"
	_ "github.com/certimate-go/certimate/migrations"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

type challengeProvider struct {
	dns.Provider
	rows                             []dns.DNSRecord
	creates, deletes, lists          int
	uncertainCreate, uncertainDelete bool
}

func (p *challengeProvider) DNSRecords(_ context.Context, zone string, page int, name string) (*dns.DNSPage[dns.DNSRecord], error) {
	if zone != "provider-zone" || name == "" {
		return nil, errors.New("unexpected zone or name")
	}
	p.lists++
	out := &dns.DNSPage[dns.DNSRecord]{Info: dns.PageInfo{Page: page, Total: len(p.rows)}}
	start := (page - 1) * dns.DNSPageSize
	if start < len(p.rows) {
		out.Items = slices.Clone(p.rows[start:min(start+dns.DNSPageSize, len(p.rows))])
	}
	return out, nil
}

func (p *challengeProvider) CreateDNSRecord(_ context.Context, zone string, in dns.RecordInput) (string, error) {
	if zone != "provider-zone" || in.TTL != 600 {
		return "", errors.New("unexpected create")
	}
	p.creates++
	id := fmt.Sprintf("remote%d", p.creates)
	p.rows = append(p.rows, dns.DNSRecord{ID: id, Name: in.Name, Type: in.Type, Content: in.Content, TTL: in.TTL, Status: "active"})
	if p.uncertainCreate {
		return "", errors.New("timeout after create")
	}
	return id, nil
}

func (p *challengeProvider) DeleteDNSRecord(_ context.Context, zone, id string) (string, error) {
	if zone != "provider-zone" {
		return "", errors.New("unexpected delete")
	}
	for i, v := range p.rows {
		if v.ID == id {
			p.rows = slices.Delete(p.rows, i, i+1)
			p.deletes++
			if p.uncertainDelete {
				return "", errors.New("timeout after delete")
			}
			return id, nil
		}
	}
	return "", errors.New("missing")
}

type challengeFixture struct {
	app           *core.BaseApp
	provider      *challengeProvider
	zone, account string
	resolve       dnscatalog.Resolve
}

func newChallengeFixture(t *testing.T) *challengeFixture {
	t.Helper()
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.ResetBootstrapState() })
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	save := func(collection string, fields map[string]any) *core.Record {
		t.Helper()
		c, err := app.FindCollectionByNameOrId(collection)
		if err != nil {
			t.Fatal(err)
		}
		r := core.NewRecord(c)
		for k, v := range fields {
			r.Set(k, v)
		}
		if err = app.Save(r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	access := save("access", map[string]any{"name": "synthetic", "provider": "cloudflare", "config": map[string]string{"apiToken": "synthetic"}})
	save("dnsAccount", map[string]any{"id": access.Id, "accessRef": access.Id})
	zone := save("dnsZone", map[string]any{"accountRef": access.Id, "providerZoneId": "provider-zone", "name": "example.test", "present": true})
	for _, id := range []string{"one", "two"} {
		_, err := app.DB().Insert("dns_cert_orders", dbx.Params{"id": id, "access_id": access.Id, "provider": "aliyun", "domain": "cert.example.test", "algorithm": "RSA2048", "request_json": "{}", "state": "pending", "created": 0, "updated": 0}).Execute()
		if err != nil {
			t.Fatal(err)
		}
	}
	f := &challengeFixture{app: app, zone: zone.Id, account: access.Id, provider: &challengeProvider{}}
	f.resolve = func(_ context.Context, provider, account string, zones bool) (dns.Provider, error) {
		if provider != "cloudflare" || account != f.account || zones {
			t.Fatal("unexpected DNS credential resolution")
		}
		return f.provider, nil
	}
	return f
}
func (f *challengeFixture) present(t *testing.T, order string, cs ...Challenge) error {
	t.Helper()
	return presentChallenges(t.Context(), f.app, order, "cert.example.test", f.zone, cs, f.resolve)
}
func (f *challengeFixture) clean(t *testing.T, order string) error {
	t.Helper()
	return cleanChallenges(t.Context(), f.app, order, f.resolve)
}

var caProof = Challenge{Name: "_dcv.cert.example.test.", Type: "TXT", Value: "synthetic-proof"}

func TestChallengeSharedOwnershipAndExternalRecords(t *testing.T) {
	f := newChallengeFixture(t)
	p := f.provider
	// Put an externally managed TXT on the second provider page. Similar
	// records on the first page must not be mistaken for this order's proof.
	for i := 0; i < dns.DNSPageSize; i++ {
		p.rows = append(p.rows, dns.DNSRecord{ID: fmt.Sprint(i), Name: caProof.Name, Type: "TXT", Content: fmt.Sprintf("independent%d", i)})
	}
	preexisting := caProof
	preexisting.Value = "previous"
	p.rows = append(p.rows, dns.DNSRecord{ID: "external", Name: caProof.Name, Type: "TXT", Content: `"previous"`})
	for _, order := range []string{"one", "one", "two"} {
		if err := f.present(t, order, preexisting, caProof); err != nil {
			t.Fatal(err)
		}
	}
	if p.creates != 1 {
		t.Fatalf("performed %d creates", p.creates)
	}
	if err := f.clean(t, "one"); err != nil {
		t.Fatal(err)
	}
	if p.deletes != 0 {
		t.Fatal("deleted a shared record")
	}
	p.uncertainDelete = true
	if err := f.clean(t, "two"); !errors.Is(err, errProvider) {
		t.Fatal(err)
	}
	if err := f.clean(t, "two"); err != nil {
		t.Fatal(err)
	}
	if p.deletes != 1 || len(p.rows) != dns.DNSPageSize+1 || p.rows[len(p.rows)-1].ID != "external" {
		t.Fatal("changed external records or retried completed deletion")
	}
}

func TestChallengeScopeAndChangedRecord(t *testing.T) {
	f := newChallengeFixture(t)
	bad := caProof
	bad.Name = "_dcv.sibling.example.test"
	if err := f.present(t, "one", caProof, bad); !errors.Is(err, errInput) {
		t.Fatal(err)
	}
	if f.provider.lists != 0 || f.provider.creates != 0 {
		t.Fatal("partial action for invalid challenge set")
	}
	if err := f.present(t, "one", caProof); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB().Update("dnsAccount", dbx.Params{"disabled": true}, dbx.HashExp{"id": f.account}).Execute(); err != nil {
		t.Fatal(err)
	}
	lists := f.provider.lists
	if err := f.clean(t, "one"); err == nil || f.provider.lists != lists {
		t.Fatal("disabled account reached provider")
	}
	if _, err := f.app.DB().Update("dnsAccount", dbx.Params{"disabled": false}, dbx.HashExp{"id": f.account}).Execute(); err != nil {
		t.Fatal(err)
	}
	f.provider.rows[0].Description = "Externally managed"
	if err := f.clean(t, "one"); !errors.Is(err, errConflict) {
		t.Fatal(err)
	}
	if f.provider.deletes != 0 {
		t.Fatal("deleted record after metadata change")
	}
	f.provider.rows[0].Content = "another token"
	if err := f.clean(t, "one"); !errors.Is(err, errConflict) {
		t.Fatal(err)
	}
	if f.provider.deletes != 0 {
		t.Fatal("deleted a different token")
	}
}

func TestChallengeAmbiguousCreateNeverAcquiresOwnership(t *testing.T) {
	f := newChallengeFixture(t)
	f.provider.uncertainCreate = true
	if err := f.present(t, "one", caProof); !errors.Is(err, errProvider) {
		t.Fatal(err)
	}
	if err := f.present(t, "two", caProof); !errors.Is(err, errConflict) {
		t.Fatal(err)
	}
	if err := f.present(t, "one", caProof); err != nil {
		t.Fatal(err)
	}
	if err := f.clean(t, "one"); err != nil {
		t.Fatal(err)
	}
	if f.provider.creates != 1 || f.provider.deletes != 0 || len(f.provider.rows) != 1 {
		t.Fatal("ambiguous create was repeated or claimed")
	}
}

func TestChallengeCleanupRequiresEveryZoneBeforeReleasingReferences(t *testing.T) {
	f := newChallengeFixture(t)
	if err := f.present(t, "one", caProof); err != nil {
		t.Fatal(err)
	}
	_, err := f.app.DB().Insert("dns_cert_challenges", dbx.Params{
		"id": "otherdns", "local_zone": "other-zone", "provider": "cloudflare",
		"access_id": "other-account", "remote_zone": "other-provider-zone", "zone_name": "other.test",
		"name": "_dcv.other.test", "type": "TXT", "value": "synthetic", "state": "external",
	}).Execute()
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.app.DB().Insert("dns_cert_challenge_refs", dbx.Params{"challenge_id": "otherdns", "order_id": "one"}).Execute()
	if err != nil {
		t.Fatal(err)
	}

	denied := errors.New("write permission revoked")
	ctx := WithChallengeZoneGuard(t.Context(), func(_ context.Context, zone string) error {
		if zone != f.zone {
			return denied
		}
		return nil
	})
	lists := f.provider.lists
	if err := cleanChallenges(ctx, f.app, "one", f.resolve); !errors.Is(err, denied) {
		t.Fatal(err)
	}
	var count int
	if err := f.app.DB().NewQuery("SELECT count(*) FROM dns_cert_challenge_refs WHERE order_id='one'").Row(&count); err != nil {
		t.Fatal(err)
	}
	if f.provider.lists != lists || f.provider.deletes != 0 || count != 2 {
		t.Fatal("partially cleaned an order without grants for every zone")
	}
}

func TestChallengeCreateRechecksGrantAfterProviderLookup(t *testing.T) {
	f := newChallengeFixture(t)
	ctx := WithChallengeZoneGuard(t.Context(), func(context.Context, string) error {
		if f.provider.lists > 0 {
			return errConflict
		}
		return nil
	})
	if err := presentChallenges(ctx, f.app, "one", "cert.example.test", f.zone, []Challenge{caProof}, f.resolve); !errors.Is(err, errConflict) {
		t.Fatal(err)
	}
	if f.provider.lists != 1 || f.provider.creates != 0 {
		t.Fatal("created a record after its grant was revoked")
	}
}
