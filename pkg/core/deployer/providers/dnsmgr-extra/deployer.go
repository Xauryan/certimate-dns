// Package dnsmgrextra implements FNOS, Kuocai and Qzyun certificate deployments.
package dnsmgrextra

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/certimate-go/certimate/pkg/core"
)

type deployer struct {
	provider                string
	username, password      string
	target, domain          string
	sshAddress, fingerprint string
	client                  *http.Client
}

var domainIDPattern = regexp.MustCompile("^[0-9]{1,32}$")
var hostLabelPattern = regexp.MustCompile("^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

func hostname(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !hostLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func field(m map[string]any, k string) string { v, _ := m[k].(string); return v }

// New validates access and target settings before a deployment is scheduled.
func New(provider string, access, config map[string]any) (core.Deployer, error) {
	d := &deployer{
		provider: provider, username: strings.TrimSpace(field(access, "username")), password: field(access, "password"),
		target: strings.TrimSpace(field(config, "target")), domain: strings.ToLower(strings.TrimSuffix(strings.TrimSpace(field(config, "domain")), ".")),
		client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	switch provider {
	case "fnos":
		host := strings.TrimSpace(field(access, "host"))
		if !hostname(host) {
			return nil, errors.New("invalid FNOS SSH hostname")
		}
		port := 22
		if v, ok := access["port"]; ok && v != nil && fmt.Sprint(v) != "" {
			p, err := strconv.Atoi(fmt.Sprint(v))
			if err != nil || p < 1 || p > 65535 {
				return nil, errors.New("invalid FNOS SSH port")
			}
			port = p
		}
		d.sshAddress = net.JoinHostPort(host, strconv.Itoa(port))
		d.fingerprint = strings.TrimSpace(field(access, "hostKeyFingerprint"))
		hashed, ok := strings.CutPrefix(d.fingerprint, "SHA256:")
		b, err := base64.RawStdEncoding.Strict().DecodeString(hashed)
		if !ok || err != nil || len(b) != 32 {
			return nil, errors.New("invalid FNOS SSH host key fingerprint")
		}
	case "kuocai":
		if !domainIDPattern.MatchString(d.target) {
			return nil, errors.New("invalid Kuocai domain ID")
		}
	case "qzyun":
		d.username = strings.TrimSpace(field(access, "email"))
		email, err := mail.ParseAddress(d.username)
		if err != nil || email.Address != d.username {
			return nil, errors.New("invalid Qzyun account email")
		}
		if d.target == "" || len(d.target) > 256 || strings.ContainsAny(d.target, "\r\n\x00") {
			return nil, errors.New("invalid Qzyun certificate name or ID")
		}
		if d.domain != "" && !hostname(strings.TrimPrefix(d.domain, "*.")) {
			return nil, errors.New("invalid Qzyun binding hostname")
		}
	default:
		return nil, errors.New("unknown certificate deployment provider")
	}
	if d.username == "" || d.password == "" {
		return nil, errors.New("missing deployment account or password")
	}
	return d, nil
}

func (*deployer) SetLogger(*slog.Logger) {}

func (d *deployer) Deploy(ctx context.Context, cert, key string) (*core.DeployerDeployResult, error) {
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		return nil, errors.New("invalid certificate or mismatched private key")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, errors.New("invalid leaf certificate")
	}
	switch d.provider {
	case "fnos":
		err = d.deployFNOS(ctx, leaf, cert, key)
	case "kuocai":
		err = d.deployKuocai(ctx, cert, key)
	case "qzyun":
		if d.domain != "" && leaf.VerifyHostname(d.domain) != nil {
			return nil, errors.New("certificate does not cover Qzyun binding hostname")
		}
		return deployQzyun(ctx, d.client, d.username, d.password, d.target, d.domain, cert, key)
	}
	if err != nil {
		return nil, err
	}
	return &core.DeployerDeployResult{}, nil
}
