package dnscert

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/certimate-go/certimate/internal/domain"
	"github.com/pocketbase/pocketbase/core"
)

// MatchesOrderDomain reports whether a leaf identifies only the single DNS name
// authorized by a commercial order. Parsing the SAN extension also accounts
// for GeneralName variants that crypto/x509 does not expose.
func MatchesOrderDomain(leaf *x509.Certificate, domain string) bool {
	if leaf == nil || leaf.IsCA || len(leaf.DNSNames) != 1 || !strings.EqualFold(leaf.DNSNames[0], domain) ||
		len(leaf.IPAddresses)+len(leaf.EmailAddresses)+len(leaf.URIs) != 0 ||
		(leaf.Subject.CommonName != "" && !strings.EqualFold(leaf.Subject.CommonName, domain)) {
		return false
	}
	if canonical, err := canonicalDomain(domain); err != nil || !strings.EqualFold(domain, canonical) {
		return false
	}
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			var names []asn1.RawValue
			rest, err := asn1.Unmarshal(ext.Value, &names)
			return err == nil && len(rest) == 0 && len(names) == 1 &&
				names[0].Class == asn1.ClassContextSpecific && names[0].Tag == 2 && !names[0].IsCompound
		}
	}
	return false
}

// Rebuild public PEM from parsed certificate DER. An unexpected block or PEM
// header in a provider response must never reach a downloadable public chain.
func validateMaterial(req OrderRequest, material Material) (*domain.Certificate, error) {
	const maxPEM = 100000 // PocketBase certificate and privateKey field limits
	if len(material.Certificate) > maxPEM || len(material.PrivateKey) > maxPEM {
		return nil, errProvider
	}
	var chain bytes.Buffer
	var leaf, previous *x509.Certificate
	remaining := bytes.TrimSpace([]byte(material.Certificate))
	for len(remaining) > 0 {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errProvider
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errProvider
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errProvider
		}
		if previous == nil {
			leaf = cert
		} else if !bytes.Equal(previous.RawIssuer, cert.RawSubject) || previous.CheckSignatureFrom(cert) != nil {
			return nil, errProvider
		}
		_ = pem.Encode(&chain, block)
		previous = cert
		remaining = bytes.TrimSpace(rest)
	}

	now := time.Now()
	if !MatchesOrderDomain(leaf, req.Domain) || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		len(leaf.UnhandledCriticalExtensions) != 0 {
		return nil, errProvider
	}
	const tlsKeyUsages = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement
	if leaf.KeyUsage != 0 && leaf.KeyUsage&tlsKeyUsages == 0 {
		return nil, errProvider
	}
	if len(leaf.ExtKeyUsage)+len(leaf.UnknownExtKeyUsage) > 0 &&
		!slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return nil, errProvider
	}
	key, rest := pem.Decode([]byte(material.PrivateKey))
	if key == nil || len(key.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errProvider
	}
	switch key.Type {
	case "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY":
	default:
		return nil, errProvider
	}
	keyPEM := pem.EncodeToMemory(key)
	if _, err := tls.X509KeyPair(chain.Bytes(), keyPEM); err != nil {
		return nil, errProvider
	}
	cert := (&domain.Certificate{}).PopulateFromX509(leaf)
	if cert.KeyAlgorithm.String() != req.Algorithm {
		return nil, errProvider
	}
	cert.Certificate = chain.String()
	cert.PrivateKey = string(keyPEM)
	_, issuerPEM := pem.Decode(chain.Bytes())
	cert.IssuerCertificate = string(issuerPEM)
	return cert, nil
}

// The caller supplies the same transaction that links this record to its order.
func storeMaterial(app core.App, req OrderRequest, provider string, material Material) (string, error) {
	cert, err := validateMaterial(req, material)
	if err != nil {
		return "", err
	}
	collection, err := app.FindCollectionByNameOrId(domain.CollectionNameCertificate)
	if err != nil {
		return "", err
	}
	record := core.NewRecord(collection)
	record.Load(map[string]any{
		"ca": provider, "source": domain.CertificateSourceTypeRequest.String(),
		"certificate": cert.Certificate, "privateKey": cert.PrivateKey, "issuerCertificate": cert.IssuerCertificate,
		"serialNumber": cert.SerialNumber, "subjectName": cert.SubjectName, "subjectAltNames": cert.SubjectAltNames,
		"issuerName": cert.IssuerName, "issuerOrg": cert.IssuerOrg, "keyAlgorithm": cert.KeyAlgorithm.String(),
		"validationPolicy": cert.ValidationPolicy.String(), "validityInterval": cert.ValidityInterval,
		"validityNotBefore": cert.ValidityNotBefore, "validityNotAfter": cert.ValidityNotAfter,
	})
	if err := app.Save(record); err != nil {
		return "", err
	}
	return record.Id, nil
}

func markRevoked(app core.App, id string) error {
	record, err := app.FindRecordById(domain.CollectionNameCertificate, id)
	if errors.Is(err, sql.ErrNoRows) {
		// Certificates may already have been removed by the local retention policy.
		return nil
	}
	if err != nil || record.GetBool("isRevoked") {
		return err
	}
	record.Set("isRevoked", true)
	return app.Save(record)
}
