// Package iisbind defines the request accepted by the Windows HTTP.sys SNI helper.
package iisbind

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/certimate-go/certimate/pkg/utils/cert/hostname"
)

const MaxRequest = 1 << 20
const Subsystem = "certimate-iis-bind"

type Request struct {
	Target      string `json:"target"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey"`
}

func Target(raw string) (string, uint16, error) {
	host, portText, hasPort := strings.Cut(strings.ToLower(strings.TrimSpace(raw)), ":")
	host = strings.TrimSuffix(host, ".")
	if !strings.Contains(host, ".") || !hostname.IsDNSName(host) || net.ParseIP(host) != nil {
		return "", 0, errors.New("a DNS hostname is required")
	}
	port := uint64(443)
	if hasPort {
		var err error
		port, err = strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			return "", 0, errors.New("invalid SNI port")
		}
	}
	return host, uint16(port), nil
}

func Read(r io.Reader) (Request, error) {
	var req Request
	raw, err := io.ReadAll(io.LimitReader(r, MaxRequest+1))
	if err != nil || len(raw) > MaxRequest {
		return req, errors.New("invalid request size")
	}
	defer clear(raw)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || dec.Decode(new(any)) != io.EOF {
		return Request{}, errors.New("invalid request")
	}
	return req, nil
}

func (r Request) Validate(now time.Time) (tls.Certificate, error) {
	host, _, err := Target(r.Target)
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(r.Certificate)+len(r.PrivateKey) > MaxRequest || r.PrivateKey == "" {
		return tls.Certificate{}, errors.New("invalid certificate material")
	}
	pair, err := tls.X509KeyPair([]byte(r.Certificate), []byte(r.PrivateKey))
	if err != nil || len(pair.Certificate) > 16 {
		return tls.Certificate{}, errors.New("invalid TLS certificate or key")
	}
	leaf := pair.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return tls.Certificate{}, errors.New("invalid TLS certificate")
		}
		pair.Leaf = leaf
	}
	if leaf.IsCA || leaf.VerifyHostname(host) != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return tls.Certificate{}, errors.New("certificate is invalid for the selected hostname and time")
	}
	if len(leaf.ExtKeyUsage)+len(leaf.UnknownExtKeyUsage) > 0 {
		valid := false
		for _, usage := range leaf.ExtKeyUsage {
			valid = valid || usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny
		}
		if !valid {
			return tls.Certificate{}, errors.New("certificate does not allow TLS server authentication")
		}
	}
	child := leaf
	for _, der := range pair.Certificate[1:] {
		parent, err := x509.ParseCertificate(der)
		if err != nil || !bytes.Equal(child.RawIssuer, parent.RawSubject) || child.CheckSignatureFrom(parent) != nil {
			return tls.Certificate{}, errors.New("invalid certificate chain")
		}
		child = parent
	}
	return pair, nil
}

func Confirmation(leaf *x509.Certificate) string {
	hash := sha256.Sum256(leaf.Raw)
	return "certimate-iis-bind/v1 " + hex.EncodeToString(hash[:]) + "\n"
}

// Creation of a new SNI record requires a separate, explicit policy flag on
// the Windows host. Rotation of existing records is the default.
func Authorize(policy string, target string) (bool, error) {
	host, port, err := Target(target)
	if err != nil {
		return false, err
	}
	seen := make(map[string]bool)
	authorized, create := false, false
	for line := range strings.SplitSeq(policy, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if len(fields) > 2 || len(fields) == 2 && fields[1] != "create" {
			return false, errors.New("invalid binding policy")
		}
		h, p, err := Target(fields[0])
		if err != nil {
			return false, errors.New("invalid binding policy")
		}
		key := net.JoinHostPort(h, strconv.Itoa(int(p)))
		if seen[key] {
			return false, errors.New("duplicate binding policy entry")
		}
		seen[key] = true
		if h == host && p == port {
			authorized, create = true, len(fields) == 2
		}
	}
	if !authorized {
		return false, errors.New("binding is not authorized")
	}
	return create, nil
}
