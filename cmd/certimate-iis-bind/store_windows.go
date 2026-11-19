//go:build windows && (amd64 || arm64)

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
	"software.sslmate.com/src/go-pkcs12"
)

var ncryptFree = windows.NewLazySystemDLL("ncrypt.dll").NewProc("NCryptFreeObject")

func openStore(name string) (windows.Handle, error) {
	str, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM_W, 0, 0, windows.CERT_SYSTEM_STORE_LOCAL_MACHINE|windows.CERT_STORE_OPEN_EXISTING_FLAG, uintptr(unsafe.Pointer(str)))
	runtime.KeepAlive(str)
	return store, err
}
func find(store windows.Handle, hash []byte) (*windows.CertContext, error) {
	blob := windows.CryptHashBlob{Size: uint32(len(hash)), Data: &hash[0]}
	return windows.CertFindCertificateInStore(store, windows.X509_ASN_ENCODING, 0, windows.CERT_FIND_SHA1_HASH, unsafe.Pointer(&blob), nil)
}
func hasKey(cert *windows.CertContext) bool {
	var handle windows.Handle
	var keySpec uint32
	var free bool
	if windows.CryptAcquireCertificatePrivateKey(cert, windows.CRYPT_ACQUIRE_SILENT_FLAG|windows.CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, nil, &handle, &keySpec, &free) != nil {
		return false
	}
	if free {
		if keySpec == windows.CERT_NCRYPT_KEY_SPEC {
			ncryptFree.Call(uintptr(handle))
		} else {
			_ = windows.CryptReleaseContext(handle, 0)
		}
	}
	return true
}
func storeCertificate(name string, p tls.Certificate, hash []byte) error {
	// Add only the verified chain's non-root intermediates to the CA store.
	for _, der := range p.Certificate[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			continue
		}
		if err = addIntermediate(der); err != nil {
			return err
		}
	}
	store, err := openStore(name)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	old, _ := find(store, hash)
	if old != nil {
		matches := bytes.Equal(unsafe.Slice(old.EncodedCert, old.Length), p.Leaf.Raw)
		usable := matches && hasKey(old)
		windows.CertFreeCertificateContext(old)
		if !matches {
			return errors.New("certificate hash collision in local store")
		}
		if usable {
			return nil
		}
	}
	// The temporary PFX never leaves process memory. No exportable-key flag is used.
	password := rand.Text()
	pfx, err := pkcs12.Modern2023.Encode(p.PrivateKey, p.Leaf, nil, password)
	if err != nil {
		return errors.New("could not encode certificate")
	}
	defer clear(pfx)
	pw, _ := windows.UTF16FromString(password)
	defer clear(pw)
	blob := windows.CryptDataBlob{Size: uint32(len(pfx)), Data: &pfx[0]}
	temp, err := windows.PFXImportCertStore(&blob, &pw[0], windows.CRYPT_MACHINE_KEYSET|windows.PKCS12_PREFER_CNG_KSP)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(temp, 0)
	leaf, err := find(temp, hash)
	if err != nil {
		return err
	}
	defer windows.CertFreeCertificateContext(leaf)
	if !hasKey(leaf) {
		return errors.New("private key association missing")
	}
	var saved *windows.CertContext
	if err = windows.CertAddCertificateContextToStore(store, leaf, windows.CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES, &saved); err != nil {
		return err
	}
	defer windows.CertFreeCertificateContext(saved)
	if !hasKey(saved) {
		return errors.New("private key not available in machine store")
	}
	return nil
}
func addIntermediate(der []byte) error {
	store, err := openStore("CA")
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	cert, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING, &der[0], uint32(len(der)))
	if err != nil {
		return err
	}
	defer windows.CertFreeCertificateContext(cert)
	return windows.CertAddCertificateContextToStore(store, cert, windows.CERT_STORE_ADD_USE_EXISTING, nil)
}
