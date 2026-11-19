package engine

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/certimate-go/certimate/internal/domain"
)

func inventoryTestCertificate(t *testing.T, id string, start, end time.Time) *domain.Certificate {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(7), DNSNames: []string{"certificate.example.test"}, NotBefore: start, NotAfter: end}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, public, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return (&domain.Certificate{Meta: domain.Meta{Id: id}}).PopulateFromPEM(
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})),
	)
}

func TestInventoryCertificateValidity(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	cert := inventoryTestCertificate(t, "testcert", now.Add(-time.Hour), now)
	if err := validateInventoryCertificate(cert, now); err == nil {
		t.Fatal("expired certificate accepted")
	}
	if err := validateInventoryCertificate(cert, now.Add(-2*time.Hour)); err == nil {
		t.Fatal("future certificate accepted")
	}
}
