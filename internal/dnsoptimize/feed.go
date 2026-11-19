// Package dnsoptimize reconciles DNS records against ranked addresses from named CDN feeds.
package dnsoptimize

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/certimate-go/certimate/internal/domain"
)

const maxFeedSize = 1 << 20
const maxRanks = 50

type Feed struct {
	Source string `json:"source"`
	CDN    string `json:"cdn"`
	Family string `json:"family"`
}

type candidates map[string][]string

type feedClient struct {
	client *http.Client
	key    func(string) string
}

func defaultFeedClient() *feedClient {
	return &feedClient{client: &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, key: os.Getenv}
}

var cdns = map[string]string{"cloudflare": "get_cloudflare_ip", "cloudfront": "get_cloudfront_ip", "gcore": "get_gcore_ip", "edgeone": "get_edgeone_ip"}
var lines = []string{"DEF", "CT", "CU", "CM"}

func (f Feed) valid() bool {
	if f.Family != "v4" && f.Family != "v6" {
		return false
	}
	switch f.Source {
	case "xingpingcn":
		return f.CDN == "cloudflare" && f.Family == "v4"
	case "hostmonit":
		return f.CDN == "cloudflare"
	case "wetest":
		return cdns[f.CDN] != ""
	}
	return false
}

func (c *feedClient) load(ctx context.Context, f Feed) (candidates, error) {
	if !f.valid() {
		return nil, domain.NewError(400, "unsupported feed, CDN or address family")
	}
	endpoint := "https://raw.githubusercontent.com/xingpingcn/enhanced-FaaS-in-China/refs/heads/main/Cf.json"
	method := http.MethodGet
	var body io.Reader
	if f.Source != "xingpingcn" {
		if f.Source == "hostmonit" {
			endpoint = "https://api.hostmonit.com/get_optimization_ip"
		} else {
			endpoint = "https://www.wetest.vip/api/cf2dns/" + cdns[f.CDN]
		}
		key := c.key("CERTIMATE_DNS_" + strings.ToUpper(f.Source) + "_KEY")
		if key == "" {
			return nil, domain.NewError(400, "configure the selected feed's API key in the server environment")
		}
		data, err := json.Marshal(map[string]string{"type": f.Family, "key": key})
		if err != nil {
			return nil, err
		}
		method = http.MethodPost
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, errors.New("invalid feed request")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	data, err := c.read(req)
	if err != nil {
		return nil, err
	}
	return parseFeed(f, data)
}

func (c *feedClient) read(req *http.Request) ([]byte, error) {
	res, err := c.client.Do(req)
	if err != nil {
		return nil, errors.New("ranked address feed is unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, errors.New("ranked address feed returned an unsuccessful status")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxFeedSize+1))
	if err != nil || len(data) > maxFeedSize {
		return nil, errors.New("could not read ranked address feed")
	}
	return data, nil
}

func parseFeed(f Feed, data []byte) (candidates, error) {
	rows := map[string][]string{}
	if f.Source == "xingpingcn" {
		var result struct {
			Cf struct{ Result map[string][]string }
		}
		if err := json.Unmarshal(data, &result); err != nil || result.Cf.Result == nil {
			return nil, errors.New("invalid ranked address feed")
		}
		// The source's default entry is a generic route. The user chooses which carrier supplies the default DNS line.
		for key, line := range map[string]string{"dianxin": "CT", "liantong": "CU", "yidong": "CM"} {
			rows[line] = result.Cf.Result[key]
		}
	} else {
		var result struct {
			Code int
			Info map[string][]struct{ IP string }
		}
		if err := json.Unmarshal(data, &result); err != nil || result.Code != 200 {
			return nil, errors.New("ranked address feed rejected the request")
		}
		for _, line := range lines {
			for _, entry := range result.Info[line] {
				rows[line] = append(rows[line], entry.IP)
			}
		}
	}
	out := candidates{}
	for _, line := range lines {
		seen := map[netip.Addr]bool{}
		for _, value := range rows[line] {
			addr, err := netip.ParseAddr(strings.TrimSpace(value))
			if err != nil || !publicIP(addr) || (f.Family == "v4") != addr.Is4() || seen[addr] {
				continue
			}
			seen[addr] = true
			out[line] = append(out[line], addr.String())
			if len(out[line]) == maxRanks {
				break
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("ranked address feed contains no usable addresses")
	}
	return out, nil
}

// Candidates become DNS data only. They are never connection targets.
func publicIP(addr netip.Addr) bool {
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.Is4In6() || addr.Zone() != "" {
		return false
	}
	for _, block := range nonPublic {
		if block.Contains(addr) {
			return false
		}
	}
	return addr.Is4() || netip.MustParsePrefix("2000::/3").Contains(addr)
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
}

type Quota struct {
	Unlimited bool  `json:"unlimited"`
	Remaining int64 `json:"remaining"`
}

// Quota only contacts the named source. Never propagate the URL or response body
// from these APIs because their fixed license endpoint takes a key in the query.
func (s *Service) Quota(ctx context.Context, source string) (Quota, error) {
	if source == "xingpingcn" {
		return Quota{Unlimited: true}, nil
	}
	endpoint := map[string]string{"hostmonit": "https://api.hostmonit.com/get_license", "wetest": "https://www.wetest.vip/api/cf2dns/get_license"}[source]
	if endpoint == "" {
		return Quota{}, domain.ErrInvalidParams
	}
	key := s.feedClient.key("CERTIMATE_DNS_" + strings.ToUpper(source) + "_KEY")
	if key == "" {
		return Quota{}, domain.NewError(400, "configure the selected feed's API key in the server environment")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+url.Values{"license": {key}}.Encode(), nil)
	if err != nil {
		return Quota{}, errors.New("invalid quota request")
	}
	body, err := s.feedClient.read(req)
	if err != nil {
		return Quota{}, err
	}
	var result struct {
		Code  int
		Count json.Number
	}
	if json.Unmarshal(body, &result) != nil || result.Code != 200 {
		return Quota{}, errors.New("could not read feed quota")
	}
	count, err := strconv.ParseInt(result.Count.String(), 10, 64)
	if err != nil || count < 0 {
		return Quota{}, errors.New("invalid feed quota")
	}
	return Quota{Remaining: count}, nil
}
