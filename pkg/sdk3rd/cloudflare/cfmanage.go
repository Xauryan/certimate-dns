package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

var (
	uuidPattern      = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
	ErrConfigChanged = errors.New("Cloudflare configuration has changed; reload before editing")
)

type ProviderStatusError struct{ Status int }

func (e *ProviderStatusError) Error() string {
	return fmt.Sprintf("Cloudflare rejected the operation (HTTP %d)", e.Status)
}

// Decode only the operation's result type. Provider messages and raw bodies can contain secrets.
func managementRequest[T any](ctx context.Context, c *Client, method, path string, query map[string]string, body any) (*dnsResult[T], error) {
	req := c.rc.R().SetContext(ctx).SetQueryParams(query).SetResponseBodyLimit(4 << 20)
	if body != nil {
		req.SetBody(body)
	}
	var out dnsResult[T]
	res, err := req.SetResult(&out).Execute(method, path)
	if err != nil {
		return nil, errors.New("Cloudflare request did not complete; refresh the resource before retrying")
	}
	if !res.IsSuccess() {
		return nil, &ProviderStatusError{Status: res.StatusCode()}
	}
	if !out.Success {
		return nil, errors.New("Cloudflare did not confirm the operation")
	}
	return &out, nil
}

func getResult[T any](ctx context.Context, c *Client, method, path string, body any) (T, error) {
	response, err := managementRequest[T](ctx, c, method, path, nil, body)
	if err != nil {
		var zero T
		return zero, err
	}
	return response.Result, nil
}

func pageResult[T any](ctx context.Context, c *Client, path string, page int, filters map[string]string) (*DNSPage[T], error) {
	if page < 1 || page > 10000000 {
		return nil, ErrInvalidDNSRequest
	}
	if filters == nil {
		filters = map[string]string{}
	}
	filters["page"] = strconv.Itoa(page)
	filters["per_page"] = strconv.Itoa(DNSPageSize)
	res, err := managementRequest[[]T](ctx, c, http.MethodGet, path, filters, nil)
	if err != nil {
		return nil, err
	}
	return &DNSPage[T]{Items: res.Result, Info: res.Info}, nil
}

func hostName(raw string) (string, error) {
	raw = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	name, err := idna.Lookup.ToASCII(raw)
	if err != nil || len(name) > 253 || !strings.Contains(name, ".") {
		return "", ErrInvalidDNSRequest
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", ErrInvalidDNSRequest
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidDNSRequest
		}
		for _, ch := range label {
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return "", ErrInvalidDNSRequest
			}
		}
	}
	return name, nil
}

type AccountSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (c *Client) Accounts(ctx context.Context, page int) (*DNSPage[AccountSummary], error) {
	return pageResult[AccountSummary](ctx, c, "/accounts", page, nil)
}

// ZoneIDByName resolves a zone without enumerating every account visible to a token.
func (c *Client) ZoneIDByName(ctx context.Context, raw string) (string, error) {
	name, err := hostName(raw)
	if err != nil {
		return "", err
	}
	page, err := pageResult[Zone](ctx, c, "/zones", 1, map[string]string{"name": name})
	if err != nil {
		return "", err
	}
	if page.Info.Total > 1 || len(page.Items) != 1 || !strings.EqualFold(page.Items[0].Name, name) || !dnsID.MatchString(page.Items[0].ID) {
		return "", errors.New("expected one accessible Cloudflare zone with this name")
	}
	return page.Items[0].ID, nil
}

func (c *Client) zoneWithAccount(ctx context.Context, zone string) (string, AccountSummary, error) {
	if !dnsID.MatchString(zone) {
		return "", AccountSummary{}, ErrInvalidDNSRequest
	}
	z, err := getResult[struct {
		Zone
		Account AccountSummary `json:"account"`
	}](ctx, c, http.MethodGet, "/zones/"+zone, nil)
	if err != nil {
		return "", AccountSummary{}, err
	}
	if z.ID != zone || !dnsID.MatchString(z.Account.ID) {
		return "", AccountSummary{}, ErrInvalidDNSRequest
	}
	name, err := hostName(z.Name)
	return name, z.Account, err
}

func (c *Client) ZoneAccount(ctx context.Context, zone string) (AccountSummary, error) {
	_, account, err := c.zoneWithAccount(ctx, zone)
	return account, err
}
