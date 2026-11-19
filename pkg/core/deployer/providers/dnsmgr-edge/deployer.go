// Package dnsmgredge implements certificate updates for DNSMgr-compatible
// administration APIs. Each operation uses the API selected by the workflow.
package dnsmgredge

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/certimate-go/certimate/pkg/core"
)

type deployer struct {
	provider string
	baseURL  string
	username string
	secret   string
	targets  []string
	certID   int64
	name     string
	client   *http.Client
}

func str(m map[string]any, name string) string {
	value, _ := m[name].(string)
	return value
}

func New(provider string, access, config map[string]any) (core.Deployer, error) {
	d := &deployer{provider: provider, username: str(access, "username"), name: strings.TrimSpace(str(config, "name")), client: &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	seen := make(map[string]bool)
	for _, raw := range strings.Split(str(config, "target"), "\n") {
		if t := strings.TrimSpace(raw); t != "" && !seen[t] {
			seen[t] = true
			d.targets = append(d.targets, t)
		}
	}
	if len(d.targets) > 100 {
		return nil, errors.New("too many certificate deployment targets")
	}
	switch provider {
	case "lucky":
		d.secret = str(access, "apiToken")
	case "xp":
		d.secret = str(access, "apiKey")
	case "uusec":
		d.secret = str(access, "password")
		if len(d.targets) == 1 {
			id, err := strconv.ParseInt(d.targets[0], 10, 64)
			if err == nil {
				d.certID = id
			}
		}
		if d.certID <= 0 || d.name == "" || d.username == "" {
			return nil, errors.New("UUSEC requires a positive certificate ID, certificate name and account")
		}
	case "westcn-vhost":
		d.baseURL = "https://api.west.cn/api/v2"
		d.secret = str(access, "apiPassword")
		if len(d.targets) != 1 || d.username == "" {
			return nil, errors.New("West.cn requires a single FTP site and API username")
		}
	default:
		return nil, errors.New("unknown certificate deployment provider")
	}
	if d.secret == "" || (len(d.targets) == 0 && provider != "lucky") {
		return nil, errors.New("missing certificate deployment credentials or target")
	}
	if d.baseURL == "" {
		raw := strings.TrimSpace(str(access, "serverUrl"))
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			return nil, errors.New("panel URL must be an HTTPS address with no credentials, query or fragment")
		}
		d.baseURL = strings.TrimRight(u.String(), "/")
	}
	return d, nil
}

func (d *deployer) SetLogger(*slog.Logger) {}

func (d *deployer) Deploy(ctx context.Context, certPEM, keyPEM string) (*core.DeployerDeployResult, error) {
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, errors.New("invalid certificate or mismatched private key")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, errors.New("invalid leaf certificate")
	}
	switch d.provider {
	case "lucky":
		err = d.deployLucky(ctx, certPEM, keyPEM, leaf)
	case "xp":
		err = d.deployXP(ctx, certPEM, keyPEM)
	case "uusec":
		err = d.deployUUSEC(ctx, certPEM, keyPEM)
	case "westcn-vhost":
		err = d.deployWest(ctx, certPEM, keyPEM, leaf)
	}
	if err != nil {
		return nil, err
	}
	return &core.DeployerDeployResult{}, nil
}

const maxResponseSize = 4 << 20

func (d *deployer) request(ctx context.Context, method, path, contentType string, body io.Reader, headers http.Header) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, d.baseURL+path, body)
	if err != nil {
		return nil, errors.New("invalid provider request")
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for name, values := range headers {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	res, err := d.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("provider connection failed; verify remote state before retrying")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("provider returned HTTP %d", res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, maxResponseSize+1))
	if err != nil || len(b) > maxResponseSize {
		return nil, errors.New("invalid provider response size")
	}
	return b, nil
}

func (d *deployer) jsonRequest(ctx context.Context, method, path string, input, output any, headers http.Header) error {
	var reader io.Reader
	contentType := ""
	if input != nil {
		b, err := json.Marshal(input)
		if err != nil {
			return errors.New("invalid provider payload")
		}
		reader = bytes.NewReader(b)
		contentType = "application/json"
	}
	b, err := d.request(ctx, method, path, contentType, reader, headers)
	if err != nil {
		return err
	}
	if json.Unmarshal(b, output) != nil {
		return errors.New("provider returned invalid JSON")
	}
	return nil
}
