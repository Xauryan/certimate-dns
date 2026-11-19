package engine

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/certimate-go/certimate/internal/domain"
)

func validateInventoryCertificate(certificate *domain.Certificate, now time.Time) error {
	if certificate == nil || certificate.IsRevoked || certificate.DeletedAt != nil {
		return fmt.Errorf("inventory certificate is unavailable")
	}
	pair, err := tls.X509KeyPair([]byte(certificate.Certificate), []byte(certificate.PrivateKey))
	if err != nil {
		return fmt.Errorf("inventory certificate and private key are invalid")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return fmt.Errorf("inventory certificate is outside its validity period")
	}
	return nil
}
