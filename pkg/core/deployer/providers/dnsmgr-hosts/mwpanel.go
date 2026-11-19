// Package dnsmgrhosts installs TLS certificates through hosting panel APIs.
package dnsmgrhosts

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/certimate-go/certimate/pkg/core"
)

// MW uses the site name as a directory and web-server configuration identifier.
var siteNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}$`)

type mwPanel struct {
	endpoint string
	appID    string
	secret   string
	sites    []string
	client   *http.Client
}

// New constructs the MW site or panel certificate deployment target. The panel
// authenticates calls to /site/set_ssl and /setting/save_panel_ssl using the
// App-Id and App-Secret headers (midoks/mdserver-web, web/admin).
func New(provider string, access, config map[string]any) (core.Deployer, error) {
	address, _ := access["serverUrl"].(string)
	u, err := url.Parse(strings.TrimSpace(address))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("MWPanel requires an HTTPS base URL")
	}
	id, _ := access["appId"].(string)
	secret, _ := access["appSecret"].(string)
	if strings.TrimSpace(id) == "" || strings.TrimSpace(secret) == "" || strings.ContainsAny(id+secret, "\r\n") {
		return nil, errors.New("MWPanel requires an app ID and app secret")
	}

	panel := &mwPanel{appID: id, secret: secret, client: &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	switch provider {
	case "mwpanel-console":
		panel.endpoint = u.JoinPath("setting", "save_panel_ssl").String()
	case "mwpanel":
		panel.endpoint = u.JoinPath("site", "set_ssl").String()
		target, _ := config["target"].(string)
		seen := make(map[string]bool)
		for raw := range strings.SplitSeq(target, "\n") {
			site := strings.TrimSpace(raw)
			if site == "" || seen[site] {
				continue
			}
			if !siteNamePattern.MatchString(site) || strings.Contains(site, "..") {
				return nil, errors.New("invalid MWPanel site name")
			}
			seen[site] = true
			panel.sites = append(panel.sites, site)
		}
		if len(panel.sites) == 0 {
			return nil, errors.New("at least one MWPanel site name is required")
		}
	default:
		return nil, errors.New("unsupported hosting panel")
	}
	return panel, nil
}

func (p *mwPanel) SetLogger(*slog.Logger) {}

func (p *mwPanel) Deploy(ctx context.Context, certPEM, privkeyPEM string) (*core.DeployerDeployResult, error) {
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(privkeyPEM)); err != nil {
		return nil, errors.New("invalid TLS certificate or private key")
	}
	if len(p.sites) == 0 {
		if err := p.upload(ctx, url.Values{"choose": {"local"}, "certPem": {certPEM}, "privateKey": {privkeyPEM}}); err != nil {
			return nil, err
		}
	} else {
		for i, site := range p.sites {
			form := url.Values{"type": {"1"}, "siteName": {site}, "csr": {certPEM}, "key": {privkeyPEM}}
			if err := p.upload(ctx, form); err != nil {
				return nil, fmt.Errorf("MWPanel site %s deployment failed (%d of %d confirmed): %w", site, i, len(p.sites), err)
			}
		}
	}
	return &core.DeployerDeployResult{}, nil
}

func (p *mwPanel) upload(ctx context.Context, form url.Values) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("invalid MWPanel request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("App-Id", p.appID)
	req.Header.Set("App-Secret", p.secret)
	resp, err := p.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("MWPanel request failed before confirmation")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("MWPanel returned HTTP %d", resp.StatusCode)
	}
	const maxBody = 64 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	var result struct {
		Status bool `json:"status"`
	}
	if err != nil || len(body) > maxBody || json.Unmarshal(body, &result) != nil || !result.Status {
		return errors.New("MWPanel did not confirm certificate deployment")
	}
	return nil
}
