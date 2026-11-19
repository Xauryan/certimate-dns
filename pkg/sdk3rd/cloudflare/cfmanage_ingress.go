package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

type IngressRule struct {
	Hostname string `json:"hostname"`
	Path     string `json:"path,omitempty"`
	Service  string `json:"service,omitempty"`
}
type PublishedRoutes struct {
	Version int64         `json:"version"`
	Rules   []IngressRule `json:"rules"`
}
type IngressChange struct {
	Zone    string `json:"zone"`
	Version int64  `json:"version"`
	IngressRule
}

type tunnelConfiguration struct {
	Version int64                      `json:"version"`
	Config  map[string]json.RawMessage `json:"config"`
}

func ingressConfig(ctx context.Context, c *Client, account, tunnel string) (string, tunnelConfiguration, []map[string]json.RawMessage, error) {
	path, err := tunnelPath(account, tunnel)
	if err != nil {
		return "", tunnelConfiguration{}, nil, err
	}
	path += "/configurations"
	config, err := getResult[tunnelConfiguration](ctx, c, http.MethodGet, path, nil)
	if err != nil {
		return "", config, nil, err
	}
	if config.Config == nil {
		config.Config = map[string]json.RawMessage{}
	}
	var rules []map[string]json.RawMessage
	if raw, ok := config.Config["ingress"]; ok {
		if err := json.Unmarshal(raw, &rules); err != nil {
			return "", config, nil, errors.New("invalid remote ingress configuration")
		}
	}
	return path, config, rules, nil
}

func stringField(data map[string]json.RawMessage, key string) string {
	var val string
	_ = json.Unmarshal(data[key], &val)
	return val
}

// Show only the service endpoint. Credentials or URL parameters in pre-existing
// provider configurations must not appear in the management UI.
func visibleService(raw string) string {
	if matched, _ := regexp.MatchString("^http_status:[1-5][0-9]{2}$", raw); matched {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func (c *Client) PublishedRoutes(ctx context.Context, account, tunnel string) (PublishedRoutes, error) {
	_, config, rules, err := ingressConfig(ctx, c, account, tunnel)
	if err != nil {
		return PublishedRoutes{}, err
	}
	out := PublishedRoutes{Version: config.Version, Rules: []IngressRule{}}
	for _, rule := range rules {
		if hostname := stringField(rule, "hostname"); hostname != "" {
			out.Rules = append(out.Rules, IngressRule{Hostname: hostname, Path: stringField(rule, "path"), Service: visibleService(stringField(rule, "service"))})
		}
	}
	return out, nil
}

// Cloudflare replaces the entire config. Serialize application edits, reread
// the latest version, and retain all untouched configuration fields verbatim.
var ingressWrite sync.Mutex

func (c *Client) ChangeIngress(ctx context.Context, account, tunnel string, in IngressChange, remove bool) error {
	return c.ChangeIngressWithZoneReader(ctx, account, tunnel, in, remove, c)
}
func (c *Client) ChangeIngressWithZoneReader(ctx context.Context, account, tunnel string, in IngressChange, remove bool, zoneReader *Client) error {
	if !dnsID.MatchString(in.Zone) || zoneReader == nil {
		return ErrInvalidDNSRequest
	}
	name, err := hostName(in.Hostname)
	if err != nil {
		return err
	}
	if len(in.Path) > 2048 || in.Version < 0 {
		return ErrInvalidDNSRequest
	}
	if _, err := regexp.Compile(in.Path); err != nil {
		return ErrInvalidDNSRequest
	}
	if !remove {
		u, err := url.Parse(in.Service)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return ErrInvalidDNSRequest
		}
	}
	ingressWrite.Lock()
	defer ingressWrite.Unlock()
	path, config, rules, err := ingressConfig(ctx, c, account, tunnel)
	if err != nil {
		return err
	}
	dns, err := zoneReader.tunnelDNS(ctx, in.Zone, account, tunnel, name)
	if err != nil {
		return err
	}
	if config.Version != in.Version {
		return ErrConfigChanged
	}
	idx := -1
	fallback := len(rules)
	for i, rule := range rules {
		h, p := stringField(rule, "hostname"), stringField(rule, "path")
		if h == "" && p == "" && i < fallback {
			fallback = i
		}
		if strings.EqualFold(h, name) && p == in.Path {
			idx = i
			break
		}
	}
	// Capture the full old configuration before changing any ingress metadata.
	old, err := json.Marshal(config.Config)
	if err != nil {
		return err
	}
	if remove {
		if idx < 0 {
			return ErrConfigChanged
		}
		rules = append(rules[:idx], rules[idx+1:]...)
	} else {
		service, _ := json.Marshal(in.Service)
		if idx >= 0 {
			rules[idx]["service"] = service
		} else {
			if fallback == len(rules) {
				rules = append(rules, map[string]json.RawMessage{"service": json.RawMessage(`"http_status:404"`)})
			}
			rule := map[string]json.RawMessage{"service": service}
			rule["hostname"], _ = json.Marshal(name)
			if in.Path != "" {
				rule["path"], _ = json.Marshal(in.Path)
			}
			rules = append(rules, nil)
			copy(rules[fallback+1:], rules[fallback:])
			rules[fallback] = rule
		}
	}
	config.Config["ingress"], err = json.Marshal(rules)
	if err != nil {
		return err
	}
	next, err := getResult[tunnelConfiguration](ctx, c, http.MethodPut, path, map[string]any{"config": config.Config})
	if err != nil {
		return err
	}
	if remove {
		for _, rule := range rules {
			if strings.EqualFold(stringField(rule, "hostname"), name) {
				return nil
			}
		}
	}
	err = dns.sync(ctx, c, remove)
	if err == nil {
		return nil
	}
	// Cloudflare replaces the entire document. Never restore over a newer
	// external edit. If the version is unverifiable, ask for reconciliation.
	_, now, _, readErr := ingressConfig(ctx, c, account, tunnel)
	if readErr != nil || next.Version <= in.Version || now.Version != next.Version {
		return errors.New("tunnel configuration changed but DNS synchronization failed; check the current ingress and CNAME")
	}
	_, rollbackErr := getResult[tunnelConfiguration](ctx, c, http.MethodPut, path, map[string]any{"config": json.RawMessage(old)})
	if rollbackErr != nil {
		return errors.New("tunnel DNS synchronization and configuration rollback failed; check the current ingress and CNAME")
	}
	return fmt.Errorf("tunnel configuration restored after CNAME synchronization failed: %w", err)
}
