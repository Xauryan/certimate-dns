package dnscert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/certimate-go/certimate/internal/domain"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

type renewalAccess struct{ a *domain.Access }

func (r renewalAccess) GetById(_ context.Context, id string) (*domain.Access, error) {
	if id != r.a.Id {
		return nil, domain.ErrRecordNotFound
	}
	return r.a, nil
}

type renewalIssuer struct {
	Issuer
	calls, reservations, verifies int
	lost                          bool
	material                      Material
}

func (i *renewalIssuer) Create(context.Context, OrderRequest) (string, error) {
	i.calls++
	i.reservations++
	if i.lost {
		return "", errProvider
	}
	return "renewed-order", nil
}
func (i *renewalIssuer) Inspect(_ context.Context, id string) (Snapshot, error) {
	i.calls++
	s := Snapshot{Domain: "order.example.test", State: "issued"}
	if id == "renewed-order" && i.verifies == 0 {
		s.State = "pending"
		s.Challenges = []Challenge{{Name: "_dcv.order.example.test", Type: "TXT", Value: "renewal-test-proof"}}
	}
	return s, nil
}
func (i *renewalIssuer) Verify(context.Context, string) error { i.calls++; i.verifies++; return nil }
func (i *renewalIssuer) Download(context.Context, string) (Material, error) {
	i.calls++
	return i.material, nil
}

type renewalFixture struct {
	*challengeFixture
	s             *Service
	issuer        *renewalIssuer
	original      Order
	certificateID string
}

func renewMaterial(t *testing.T, validity time.Duration) Material {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(int64(validity.Hours())), DNSNames: []string{"order.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(validity)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return Material{Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))}
}

func setupRenewal(t *testing.T) *renewalFixture {
	t.Helper()
	f := newChallengeFixture(t)
	c, err := f.app.FindCollectionByNameOrId("access")
	if err != nil {
		t.Fatal(err)
	}
	r := core.NewRecord(c)
	r.Load(map[string]any{"name": "Synthetic CA", "provider": "tencentcloud", "config": map[string]string{"secretId": "synthetic"}})
	if err := f.app.Save(r); err != nil {
		t.Fatal(err)
	}
	a := &domain.Access{Provider: "tencentcloud"}
	a.Id = r.Id
	i := &renewalIssuer{material: renewMaterial(t, 90*24*time.Hour)}
	s := NewService(renewalAccess{a}, f.resolve)
	s.issuer = func(*domain.Access) (Issuer, error) { return i, nil }
	req := OrderRequest{Domain: "order.example.test", Algorithm: "EC256", Email: "operator@example.test"}
	o, err := s.Draft(t.Context(), f.app, a.Id, req)
	if err != nil {
		t.Fatal(err)
	}
	id, err := storeMaterial(f.app, req, o.Provider, renewMaterial(t, 24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.app.DB().Update("dns_cert_orders", dbx.Params{"state": "issued", "remote_id": "original", "certificate_id": id}, dbx.HashExp{"id": o.ID}).Execute()
	if err != nil {
		t.Fatal(err)
	}
	return &renewalFixture{f, s, i, o, id}
}
func (f *renewalFixture) config(t *testing.T) Renewal {
	t.Helper()
	r, err := ReadRenewal(f.app, f.original.ID)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func (f *renewalFixture) enable(t *testing.T) Renewal {
	t.Helper()
	on := true
	r, err := f.s.SetRenewal(t.Context(), f.app, f.original.ID, RenewalInput{Version: f.config(t).Version, ZoneID: f.zone, Enabled: &on, ConfirmQuota: true})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func (f *renewalFixture) tick(t *testing.T, force bool) Renewal {
	t.Helper()
	if force {
		_, err := f.app.DB().Update("dns_cert_renewals", dbx.Params{"next_at": time.Now().Unix()}, dbx.HashExp{"root_id": f.original.ID}).Execute()
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := f.s.RunRenewals(t.Context(), f.app); err != nil {
		t.Fatal(err)
	}
	return f.config(t)
}

func TestRenewalLifecycle(t *testing.T) {
	f := setupRenewal(t)
	on := true
	if _, err := f.s.SetRenewal(t.Context(), f.app, f.original.ID, RenewalInput{ZoneID: f.zone, Enabled: &on}); !errors.Is(err, errInput) {
		t.Fatalf("quota opt-in %v", err)
	}
	f.tick(t, false)
	if f.issuer.calls != 0 {
		t.Fatal("unconfigured schedule contacted issuer")
	}
	f.enable(t)
	// More than one scheduler may see the same due row. Only one can allocate
	// the next order. Issuance runs later against the persisted successor id.
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			if err := f.s.RunRenewals(t.Context(), f.app); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	r := f.config(t)
	if r.PendingOrderID == "" || f.issuer.reservations != 0 {
		t.Fatal("missing local successor or premature reservation", r.Status)
	}
	childID := r.PendingOrderID
	for n := 0; n < 12 && r.PendingOrderID != ""; n++ {
		r = f.tick(t, true)
	}
	if r.CurrentOrderID != childID || r.PendingOrderID != "" || r.Status != "scheduled" || r.NextAt < time.Now().Add(74*24*time.Hour).Unix() {
		t.Fatalf("unexpected chain progression: %+v", r)
	}
	if f.issuer.reservations != 1 || f.issuer.verifies != 1 || f.provider.creates != 1 || f.provider.deletes != 1 {
		t.Fatal("unexpected number of provider writes")
	}
	original, err := f.app.FindRecordById("certificate", f.certificateID)
	if err != nil || !original.GetBool("isRenewed") {
		t.Fatal("original certificate not marked renewed", err)
	}
	childConfig, err := ReadRenewal(f.app, childID)
	if err != nil || childConfig.RootID != r.RootID {
		t.Fatal("schedule not linked to successful successor")
	}
	f.tick(t, false)
	if f.issuer.reservations != 1 {
		t.Fatal("new certificate immediately consumed an additional quota")
	}
}

func TestRenewalSuspendsAfterZoneDisabledOrUncertainPurchase(t *testing.T) {
	t.Run("disabled zone", func(t *testing.T) {
		f := setupRenewal(t)
		f.enable(t)
		if _, err := f.app.DB().Update("dnsAccount", dbx.Params{"disabled": true}, dbx.HashExp{"id": f.account}).Execute(); err != nil {
			t.Fatal(err)
		}
		r := f.tick(t, false)
		if r.Status != "needs_review" || r.NextAt != 0 || f.issuer.calls != 0 {
			t.Fatal("disabled zone did not stop renewal")
		}
	})
	t.Run("ambiguous reservation", func(t *testing.T) {
		f := setupRenewal(t)
		f.issuer.lost = true
		f.enable(t)
		r := f.tick(t, false)
		if r.PendingOrderID == "" {
			t.Fatal("missing successor")
		}
		f.tick(t, true)
		r = f.tick(t, true)
		f.tick(t, false)
		if f.issuer.reservations != 1 || r.Status != "needs_review" || r.NextAt != 0 {
			t.Fatal("ambiguous purchase was retried")
		}
	})
	t.Run("edited child", func(t *testing.T) {
		f := setupRenewal(t)
		f.enable(t)
		r := f.tick(t, false)
		o, err := ReadOrder(f.app, r.PendingOrderID)
		if err != nil {
			t.Fatal(err)
		}
		req := OrderRequest{SourceZoneID: f.zone, Domain: "another.example.test", Algorithm: "EC256", Email: "operator@example.test"}
		_, err = f.s.Act(t.Context(), f.app, o.ID, "edit", ActionInput{Version: o.Version, Request: &req})
		if err != nil {
			t.Fatal(err)
		}
		r = f.tick(t, true)
		if r.Status != "needs_review" || f.issuer.reservations != 0 {
			t.Fatal("automation followed a modified order")
		}
	})
}
