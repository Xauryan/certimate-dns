package dnscert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/certimate-go/certimate/internal/domain"
	_ "github.com/certimate-go/certimate/migrations"
	"github.com/pocketbase/pocketbase/core"
)

func testOrderMaterial(t *testing.T, leafKey crypto.Signer, changes ...func(*x509.Certificate)) (Material, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test issuer", Organization: []string{"Test Org"}},
		IsCA:         true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "order.example.test"}, DNSNames: []string{"order.example.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
	}
	for _, change := range changes {
		change(leaf)
	}
	makeCert := func(cert *x509.Certificate, key crypto.Signer) string {
		t.Helper()
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, key.Public(), caKey)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	key, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer := makeCert(ca, caKey)
	return Material{
		Certificate: makeCert(leaf, leafKey) + issuer,
		PrivateKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})),
	}, issuer
}

func TestOrderMaterialIdentity(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m, issuer := testOrderMaterial(t, ec)
	other, wrongIssuer := testOrderMaterial(t, rsaKey)
	clientOnly, _ := testOrderMaterial(t, ec, func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	})
	unsuitableKey, _ := testOrderMaterial(t, ec, func(c *x509.Certificate) {
		c.KeyUsage = x509.KeyUsageCRLSign
	})
	unknownCritical, _ := testOrderMaterial(t, ec, func(c *x509.Certificate) {
		c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Critical: true, Value: []byte{5, 0}}}
	})
	req := OrderRequest{Domain: "order.example.test", Algorithm: "EC256"}
	type vector struct {
		name     string
		request  OrderRequest
		material Material
	}
	for _, tc := range []vector{
		{"wrong domain", OrderRequest{Domain: "elsewhere.example.test", Algorithm: "EC256"}, m},
		{"wrong algorithm", req, other},
		{"wrong key", req, Material{Certificate: m.Certificate, PrivateKey: other.PrivateKey}},
		{"secret in public bundle", req, Material{Certificate: m.Certificate + m.PrivateKey, PrivateKey: m.PrivateKey}},
		{"invalid intermediate", req, Material{Certificate: strings.TrimSuffix(m.Certificate, issuer) + wrongIssuer, PrivateKey: m.PrivateKey}},
		{"multiple keys", req, Material{Certificate: m.Certificate, PrivateKey: m.PrivateKey + other.PrivateKey}},
		{"corrupt public chain", req, Material{Certificate: m.Certificate + "metadata", PrivateKey: m.PrivateKey}},
		{"absent key", req, Material{Certificate: m.Certificate}},
		{"client certificate", req, clientOnly},
		{"non-TLS key usage", req, unsuitableKey},
		{"unhandled critical extension", req, unknownCritical},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := validateMaterial(tc.request, tc.material); !errors.Is(err, errProvider) {
				t.Fatal("accepted invalid provider keypair or returned nonsanitized error")
			}
		})
	}
	if _, err := validateMaterial(OrderRequest{Domain: req.Domain, Algorithm: "RSA2048"}, other); err != nil {
		t.Fatal("valid RSA2048 chain was rejected")
	}
}

func TestOrderMaterialSingleDomain(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	req := OrderRequest{Domain: "order.example.test", Algorithm: "EC256"}
	withOpaqueName, err := asn1.Marshal([]asn1.RawValue{
		{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(req.Domain)},
		{Class: asn1.ClassContextSpecific, Tag: 8, Bytes: []byte{42, 3, 4}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*x509.Certificate)
		valid  bool
	}{
		{"single DNS SAN without CN", func(c *x509.Certificate) { c.Subject.CommonName = "" }, true},
		{"case-insensitive DNS name", func(c *x509.Certificate) { c.DNSNames[0] = strings.ToUpper(req.Domain) }, true},
		{"CN only", func(c *x509.Certificate) { c.DNSNames = nil }, false},
		{"different CN", func(c *x509.Certificate) { c.Subject.CommonName = "other.example.test" }, false},
		{"wildcard", func(c *x509.Certificate) { c.DNSNames = []string{"*.example.test"} }, false},
		{"additional DNS SAN", func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, "other.example.test") }, false},
		{"additional IP SAN", func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)} }, false},
		{"additional mail SAN", func(c *x509.Certificate) { c.EmailAddresses = []string{"admin@example.test"} }, false},
		{"additional URI SAN", func(c *x509.Certificate) { c.URIs = []*url.URL{{Scheme: "spiffe", Host: "example.test"}} }, false},
		{"additional registered ID", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: withOpaqueName}}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := testOrderMaterial(t, key, tc.change)
			_, err := validateMaterial(req, m)
			if tc.valid && err != nil || !tc.valid && !errors.Is(err, errProvider) {
				t.Fatalf("unexpected material validation result: %v", err)
			}
		})
	}
}

func TestOrderMaterialStoredWithCertificateSchema(t *testing.T) {
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.ResetBootstrapState() })
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m, issuer := testOrderMaterial(t, key)
	req := OrderRequest{Domain: "order.example.test", Algorithm: "EC256"}
	var rolledBackID string
	abort := errors.New("synthetic order update failure")
	err = app.RunInTransaction(func(tx core.App) error {
		var err error
		rolledBackID, err = storeMaterial(tx, req, "testissuer", m)
		if err != nil {
			return err
		}
		return abort
	})
	if !errors.Is(err, abort) {
		t.Fatal("could not simulate an interrupted order update")
	}
	if _, err := app.FindRecordById(domain.CollectionNameCertificate, rolledBackID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("certificate record survived rollback")
	}
	if err := markRevoked(app, rolledBackID); err != nil {
		t.Fatal("missing certificate blocked order reconciliation")
	}

	var id string
	err = app.RunInTransaction(func(tx core.App) error {
		var err error
		id, err = storeMaterial(tx, req, "testissuer", m)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := app.FindRecordById(domain.CollectionNameCertificate, id)
	if err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]string{
		"certificate": m.Certificate, "privateKey": m.PrivateKey, "issuerCertificate": issuer, "source": "request", "ca": "testissuer",
		"keyAlgorithm": "EC256", "subjectName": req.Domain, "subjectAltNames": req.Domain, "issuerOrg": "Test Org", "issuerName": "Test issuer", "serialNumber": "2",
	} {
		if record.GetString(field) != want {
			t.Errorf("unexpected value for field %s", field)
		}
	}
	if record.GetInt("validityInterval") != 25*3600 || record.GetDateTime("validityNotAfter").Time().IsZero() || record.GetBool("isRevoked") {
		t.Fatal("incorrect validity or revocation status")
	}
	for range 2 {
		if err := markRevoked(app, id); err != nil {
			t.Fatal(err)
		}
	}
	record, err = app.FindRecordById(domain.CollectionNameCertificate, id)
	if err != nil || !record.GetBool("isRevoked") {
		t.Fatal("revocation was not persisted")
	}
}
