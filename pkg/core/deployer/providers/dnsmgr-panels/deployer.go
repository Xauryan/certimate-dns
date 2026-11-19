// Package dnsmgrpanels deploys certificates to hosting panels using their
// authenticated certificate installation forms and APIs.
package dnsmgrpanels

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/certimate-go/certimate/pkg/core"
)

type panel struct {
	provider                   string
	baseURL                    *url.URL
	username, password, secret string
	adminPath                  string
	targets, domains           []string
	client                     *http.Client
}

func field(m map[string]any, k string) string {
	v, _ := m[k].(string)
	return v
}

var hostLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func validDomain(v string) bool {
	if len(v) > 253 || v == "" {
		return false
	}
	for _, label := range strings.Split(v, ".") {
		if !hostLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func targets(config map[string]any, key string, domain bool) ([]string, error) {
	input, ok := config[key]
	if !ok || input == nil {
		return nil, nil
	}
	v, ok := input.(string)
	if !ok {
		return nil, errors.New("invalid panel target list")
	}
	var result []string
	seen := make(map[string]bool)
	for _, raw := range strings.FieldsFunc(v, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' }) {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if domain {
			value = strings.ToLower(value)
			if !validDomain(value) {
				return nil, errors.New("invalid site domain")
			}
		}
		if !seen[value] {
			result = append(result, value)
			seen[value] = true
		}
	}
	if len(result) == 0 && strings.TrimSpace(v) != "" {
		return nil, errors.New("empty panel target list")
	}
	return result, nil
}

func New(provider string, access, config map[string]any) (core.Deployer, error) {
	u, err := url.Parse(strings.TrimSpace(field(access, "serverUrl")))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("panel URL must be an HTTPS address without embedded credentials, query or fragment")
	}
	p := &panel{provider: provider, baseURL: u, username: field(access, "username"), password: field(access, "password"),
		client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	p.targets, err = targets(config, "target", provider != "kangleadmin")
	if err != nil {
		return nil, err
	}
	switch provider {
	case "kangle", "kangleadmin", "kangleadmin-console":
		p.secret = field(access, "securityKey")
		p.adminPath = strings.TrimRight(strings.TrimSpace(field(access, "adminPath")), "/")
		if p.adminPath == "" {
			p.adminPath = "/admin"
		}
		if !strings.HasPrefix(p.adminPath, "/") || strings.ContainsAny(p.adminPath, "?#%\\") || path.Clean(p.adminPath) != p.adminPath {
			return nil, errors.New("invalid Kangle administration path")
		}
		if p.username == "" || (provider == "kangle" && (p.secret == "") == (p.password == "")) || (provider != "kangle" && p.secret == "") {
			return nil, errors.New("Kangle account credentials are incomplete or ambiguous")
		}
		if provider == "kangleadmin" {
			p.domains, err = targets(config, "domains", true)
			if err != nil {
				return nil, err
			}
		}
	case "cloudpanel", "directadmin":
		if p.username == "" || p.password == "" {
			return nil, errors.New("panel username and password are required")
		}
		if provider == "directadmin" && (strings.Trim(u.Path, "/") != "" || strings.Contains(p.username, ":")) {
			return nil, errors.New("invalid DirectAdmin address or account")
		}
	default:
		return nil, errors.New("unknown panel deployment provider")
	}
	if len(p.targets) == 0 && provider != "kangle" && provider != "kangleadmin-console" {
		return nil, errors.New("panel deployment requires at least one target")
	}
	return p, nil
}

func (p *panel) SetLogger(*slog.Logger) {}

// Each deployment owns its login state. Sharing a jar across concurrent site
// switches could install a key in a different Kangle virtual host.
func (p *panel) Deploy(ctx context.Context, cert, key string) (*core.DeployerDeployResult, error) {
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		return nil, errors.New("invalid certificate or mismatched private key")
	}
	session := *p
	client := *p.client
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		return nil, errors.New("failed to initialize panel session")
	}
	session.client = &client
	switch p.provider {
	case "directadmin":
		err = session.deployDirectAdmin(ctx, cert, key, pair.PrivateKey)
	case "cloudpanel":
		err = session.deployCloudPanel(ctx, cert, key)
	default:
		err = session.deployKangle(ctx, cert, key)
	}
	if err != nil {
		return nil, err
	}
	return &core.DeployerDeployResult{}, nil
}

type reply struct {
	status   int
	body     string
	location *url.URL
}

func (p *panel) endpoint(route string, query url.Values) *url.URL {
	u := *p.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + route
	u.RawPath = ""
	u.RawQuery = query.Encode()
	return &u
}

// Redirects are observed as acknowledgements and never followed with a POST.
// Never return a transport error, Location, response body or signed URL to logs.
func (p *panel) call(ctx context.Context, route string, query, form url.Values, referer string) (*reply, error) {
	u := p.endpoint(route, query)
	var reader io.Reader
	method := http.MethodGet
	if form != nil {
		reader = strings.NewReader(form.Encode())
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return nil, errors.New("invalid panel request")
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", u.Scheme+"://"+u.Host)
	}
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	if p.provider == "directadmin" {
		req.SetBasicAuth(p.username, p.password)
	}
	res, err := p.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("panel connection failed before confirmation")
	}
	defer res.Body.Close()
	const maxBody = 4 << 20
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil || len(b) > maxBody {
		return nil, errors.New("invalid panel response size")
	}
	out := &reply{status: res.StatusCode, body: string(b)}
	if loc := res.Header.Get("Location"); loc != "" {
		result, err := u.Parse(loc)
		if err != nil || result.User != nil || result.Scheme != u.Scheme || !strings.EqualFold(result.Host, u.Host) {
			return nil, errors.New("invalid or external panel redirect")
		}
		out.location = result
	}
	return out, nil
}

func forTargets(targets []string, install func(string) error) error {
	for i, target := range targets {
		if err := install(target); err != nil {
			return fmt.Errorf("%d of %d panel updates confirmed: %w", i, len(targets), err)
		}
	}
	return nil
}
