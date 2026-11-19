// Package selfhostutil shares request and record handling between DNS API adapters.
package selfhostutil

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/maphash"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	xhttp "github.com/certimate-go/certimate/pkg/utils/http"
)

var ErrProvider = errors.New("DNS provider request failed; refresh before retrying a change")

func Field(a *domain.Access, name string) string {
	return dnsutil.Field(a, name)
}

type Client struct {
	Base string
	HTTP *http.Client
}

func NewClient(base string) (*Client, error) {
	return NewClientWithHTTP(base, dnsutil.NewHTTPClient())
}

func NewClientWithHTTP(base string, client *http.Client) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, domain.ErrInvalidParams
	}
	return &Client{strings.TrimRight(u.String(), "/"), client}, nil
}

// ApplyTLSConfig honors the existing per-account certificate verification option.
func (c *Client) ApplyTLSConfig(a *domain.Access) {
	if skip, _ := a.Config["allowInsecureConnections"].(bool); skip {
		var transport *http.Transport
		switch current := c.HTTP.Transport.(type) {
		case *http.Transport:
			transport = current.Clone()
		case nil:
			transport = xhttp.NewDefaultTransport()
		default:
			return // Custom round-trippers own their TLS configuration.
		}
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}
		transport.TLSClientConfig.InsecureSkipVerify = true
		c.HTTP.Transport = transport
	}
}

// Some providers accept only whole record sets, or acknowledge creates without
// returning an ID. Serialize read/modify/write sequences across resolver instances.
var zoneLocks [127]sync.Mutex
var lockSeed = maphash.MakeSeed()

func LockZone(endpoint, zone string) func() {
	lock := &zoneLocks[maphash.String(lockSeed, endpoint+"\x00"+zone)%uint64(len(zoneLocks))]
	lock.Lock()
	return lock.Unlock
}

func CompletePage(page, total, size int) bool {
	return PageOK(page) && total >= 0 && size == min(dns.DNSPageSize, max(0, total-(page-1)*dns.DNSPageSize))
}

// Call accepts a provider-owned path and sends authentication through headers or a form body.
func (c *Client) Call(ctx context.Context, method, path string, query url.Values, body any, headers http.Header, out any) error {
	var payload io.Reader
	mime := "application/json"
	switch v := body.(type) {
	case nil:
	case url.Values:
		payload = strings.NewReader(v.Encode())
		mime = "application/x-www-form-urlencoded"
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return ErrProvider
		}
		payload = bytes.NewReader(b)
	}
	endpoint := c.Base + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, payload)
	if err != nil {
		return ErrProvider
	}
	for k, vals := range headers {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Content-Type", mime)
	res, err := c.HTTP.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrProvider
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return ErrProvider
	}
	if out == nil {
		return nil
	}
	const maxSize = 32 << 20
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxSize+1))
	if err != nil || len(raw) > maxSize || json.Unmarshal(raw, out) != nil {
		return ErrProvider
	}
	return nil
}

func PageOK(p int) bool { return dnsutil.ValidPage(p) }

func SlicePage[T any](rows []T, page int) (*dns.DNSPage[T], error) {
	return dnsutil.SlicePage(rows, page)
}

func Name(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }

func Relative(name, zone string) (string, error) {
	return dnsutil.RelativeName(name, zone)
}

func Full(host, zone string) string {
	if host == "" || host == "@" {
		return Name(zone)
	}
	return Name(host) + "." + Name(zone)
}
func Status(disabled bool) string {
	if disabled {
		return "disabled"
	}
	return "active"
}

func ID(zone, name, typ, content string) string {
	raw, _ := json.Marshal([4]string{zone, Name(name), typ, content})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// Text accepts integer or string IDs without passing large provider IDs through float64.
type Text string

func (v *Text) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, []byte("null")) {
		*v = ""
		return nil
	}
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*v = Text(s)
		return nil
	}
	if _, err := strconv.ParseInt(string(b), 10, 64); err != nil {
		return ErrProvider
	}
	*v = Text(b)
	return nil
}
