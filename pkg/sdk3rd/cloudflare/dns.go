package cloudflare

import (
	"context"
	"errors"
	"fmt"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	"net/http"
	"regexp"
	"strconv"
)

const DNSPageSize = dns.DNSPageSize

type Zone = dns.Zone
type DNSRecord = dns.DNSRecord
type DNSPage[T any] = dns.DNSPage[T]
type RecordInput = dns.RecordInput
type RecordPatch = dns.RecordPatch
type PageInfo = dns.PageInfo

var dnsID = regexp.MustCompile("^[0-9a-f]{32}$")
var ErrInvalidDNSRequest = dns.ErrInvalidDNSRequest

type dnsResult[T any] struct {
	sdkResponseBase
	Result T        `json:"result"`
	Info   PageInfo `json:"result_info"`
}

// Return provider status codes without echoing provider response bodies, which may contain DNS record values.
func dnsRequest[T any](ctx context.Context, c *Client, method, path string, query map[string]string, body any) (*dnsResult[T], error) {
	req := c.rc.R().SetContext(ctx).SetQueryParams(query)
	if body != nil {
		req.SetBody(body)
	}
	var result dnsResult[T]
	res, err := req.SetResult(&result).Execute(method, path)
	if err != nil {
		return nil, errors.New("Cloudflare request did not complete; refresh before retrying a change")
	}
	if res.StatusCode() != http.StatusOK || !result.Success {
		return nil, fmt.Errorf("Cloudflare rejected the DNS request (HTTP %d)", res.StatusCode())
	}
	return &result, nil
}

func listDNS[T any](ctx context.Context, c *Client, path string, page int, filter map[string]string) (*DNSPage[T], error) {
	if page < 1 {
		return nil, ErrInvalidDNSRequest
	}
	filter["page"] = strconv.Itoa(page)
	filter["per_page"] = strconv.Itoa(DNSPageSize)
	result, err := dnsRequest[[]T](ctx, c, http.MethodGet, path, filter, nil)
	if err != nil {
		return nil, err
	}
	return &DNSPage[T]{Items: result.Result, Info: result.Info}, nil
}

func (c *Client) Zones(ctx context.Context, page int) (*DNSPage[Zone], error) {
	return listDNS[Zone](ctx, c, "/zones", page, map[string]string{})
}

func (c *Client) DNSRecords(ctx context.Context, zone string, page int, name string) (*DNSPage[DNSRecord], error) {
	if !dnsID.MatchString(zone) {
		return nil, ErrInvalidDNSRequest
	}
	filter := map[string]string{}
	if name != "" {
		filter["name.contains"] = name
	}
	return listDNS[DNSRecord](ctx, c, "/zones/"+zone+"/dns_records", page, filter)
}

func (c *Client) CreateDNSRecord(ctx context.Context, zone string, input RecordInput) (string, error) {
	if !dnsID.MatchString(zone) {
		return "", ErrInvalidDNSRequest
	}
	return writeRecord(ctx, c, http.MethodPost, "/zones/"+zone+"/dns_records", input)
}

func (c *Client) PatchDNSRecord(ctx context.Context, zone, id string, input RecordPatch) (string, error) {
	if !dnsID.MatchString(zone) || !dnsID.MatchString(id) {
		return "", ErrInvalidDNSRequest
	}
	return writeRecord(ctx, c, http.MethodPatch, "/zones/"+zone+"/dns_records/"+id, input)
}

func (c *Client) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	if !dnsID.MatchString(zone) || !dnsID.MatchString(id) {
		return "", ErrInvalidDNSRequest
	}
	return writeRecord(ctx, c, http.MethodDelete, "/zones/"+zone+"/dns_records/"+id, nil)
}

func writeRecord(ctx context.Context, c *Client, method, path string, input any) (string, error) {
	result, err := dnsRequest[DNSRecord](ctx, c, method, path, nil, input)
	if err != nil {
		return "", err
	}
	if !dnsID.MatchString(result.Result.ID) {
		return "", errors.New("missing Cloudflare record ID; refresh the record list")
	}
	return result.Result.ID, nil
}

func (c *Client) ExportDNSZone(ctx context.Context, zone string) (string, error) {
	if !dnsID.MatchString(zone) {
		return "", ErrInvalidDNSRequest
	}
	res, err := c.rc.R().SetContext(ctx).SetHeader("Accept", "text/plain").Get("/zones/" + zone + "/dns_records/export")
	if err != nil {
		return "", errors.New("Cloudflare zone export did not complete")
	}
	if res.StatusCode() != http.StatusOK {
		return "", fmt.Errorf("Cloudflare rejected the zone export (HTTP %d)", res.StatusCode())
	}
	return string(res.Body()), nil
}
