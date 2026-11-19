package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	zonefile "github.com/miekg/dns"
	"net/http"
	"regexp"
	"strconv"
	"strings"
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
	req := c.rc.R().SetResponseBodyLimit(8 << 20).SetContext(ctx).SetQueryParams(query)
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
	if !dnsutil.ValidPage(page) {
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
	rows, err := listDNS[wireRecord](ctx, c, "/zones/"+zone+"/dns_records", page, filter)
	if err != nil {
		return nil, err
	}
	result := &DNSPage[DNSRecord]{Info: rows.Info, Items: make([]DNSRecord, 0, len(rows.Items))}
	for _, row := range rows.Items {
		result.Items = append(result.Items, row.record())
	}
	return result, nil
}

func (c *Client) CreateDNSRecord(ctx context.Context, zone string, input RecordInput) (string, error) {
	if !dnsID.MatchString(zone) {
		return "", ErrInvalidDNSRequest
	}
	body, err := cloudflareContent(input.Type, input.Content, input.Priority)
	if err != nil {
		return "", err
	}
	body["type"] = input.Type
	body["name"] = input.Name
	body["ttl"] = input.TTL
	switch input.Line {
	case "":
	case "0", "1":
		if input.Line == "1" && input.Type != "A" && input.Type != "AAAA" && input.Type != "CNAME" {
			return "", ErrInvalidDNSRequest
		}
		body["proxied"] = input.Line == "1"
	default:
		return "", ErrInvalidDNSRequest
	}
	if input.Weight != nil {
		return "", ErrInvalidDNSRequest
	}
	if input.Description != "" {
		body["comment"] = input.Description
	}
	return writeRecord(ctx, c, http.MethodPost, "/zones/"+zone+"/dns_records", body)
}

func (c *Client) PatchDNSRecord(ctx context.Context, zone, id string, input RecordPatch) (string, error) {
	if !dnsID.MatchString(zone) || !dnsID.MatchString(id) {
		return "", ErrInvalidDNSRequest
	}
	row, err := c.writableRecord(ctx, zone, id)
	if err != nil {
		return "", err
	}
	// MX and URI priority is separate from content. A missing priority cannot be reconstructed from the edit.
	if (row.Type == "MX" || row.Type == "URI") && row.Priority == nil {
		return "", ErrInvalidDNSRequest
	}
	body, err := cloudflareContent(row.Type, input.Content, row.Priority)
	if err != nil {
		return "", err
	}
	body["ttl"] = input.TTL
	return writeRecord(ctx, c, http.MethodPatch, "/zones/"+zone+"/dns_records/"+id, body)
}

func (c *Client) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	if !dnsID.MatchString(zone) || !dnsID.MatchString(id) {
		return "", ErrInvalidDNSRequest
	}
	if _, err := c.writableRecord(ctx, zone, id); err != nil {
		return "", err
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

type wireRecord struct {
	ModifiedOn string `json:"modified_on"`
	DNSRecord
	Comment  string `json:"comment"`
	ZoneName string `json:"zone_name"`
	Locked   bool   `json:"locked"`
	Meta     struct {
		ManagedByApps       bool `json:"managed_by_apps"`
		ManagedByArgoTunnel bool `json:"managed_by_argo_tunnel"`
		ReadOnly            bool `json:"read_only"`
	} `json:"meta"`
	Data struct {
		Priority *int   `json:"priority"`
		Weight   *int   `json:"weight"`
		Port     *int   `json:"port"`
		Target   string `json:"target"`
	} `json:"data"`
}

func (r wireRecord) record() DNSRecord {
	rec := r.DNSRecord
	rec.UpdatedAt = r.ModifiedOn
	rec.Description = r.Comment
	rec.ReadOnly = r.Locked || r.Meta.ReadOnly || r.Meta.ManagedByApps || r.Meta.ManagedByArgoTunnel
	rec.Line = "0"
	if rec.Proxied {
		rec.Line = "1"
	}
	if r.ZoneName != "" {
		owner, err := dnsutil.RelativeName(r.Name, r.ZoneName)
		if err == nil {
			rec.Status = "enabled"
			if strings.HasSuffix(owner, "_pause") {
				rec.Status = "disabled"
			}
		}
	}
	switch rec.Type {
	case "SRV":
		d := r.Data
		if d.Priority != nil && d.Weight != nil && d.Port != nil && d.Target != "" {
			rec.Content = fmt.Sprintf("%d %d %d %s", *d.Priority, *d.Weight, *d.Port, d.Target)
			rec.Priority = d.Priority
		}
	case "URI":
		if r.Data.Weight != nil && r.Data.Target != "" {
			rec.Content = fmt.Sprintf("%d %s", *r.Data.Weight, strconv.Quote(r.Data.Target))
		}
	}
	return rec
}
func (c *Client) writableRecord(ctx context.Context, zone, id string) (*DNSRecord, error) {
	r, err := dnsRequest[wireRecord](ctx, c, "GET", "/zones/"+zone+"/dns_records/"+id, nil, nil)
	if err != nil {
		return nil, err
	}
	record := r.Result.record()
	if record.ID != id || record.Type == "" || record.Name == "" || record.ReadOnly {
		return nil, ErrInvalidDNSRequest
	}
	return &record, nil
}
func cloudflareContent(typ, content string, priority *int) (map[string]any, error) {
	body := map[string]any{"content": content}
	if typ == "MX" || typ == "URI" {
		p := 1
		if priority != nil {
			p = *priority
		}
		if p < 0 || p > 65535 {
			return nil, ErrInvalidDNSRequest
		}
		body["priority"] = p
	}
	switch typ {
	case "CAA", "URI", "SRV":
		if strings.ContainsAny(content, "\r\n") {
			return nil, ErrInvalidDNSRequest
		}
		dataText := content
		if typ == "URI" {
			dataText = "0 " + content
		}
		rr, err := zonefile.NewRR(". 60 IN " + typ + " " + dataText)
		if err != nil || rr == nil {
			return nil, ErrInvalidDNSRequest
		}
		delete(body, "content")
		switch r := rr.(type) {
		case *zonefile.CAA:
			body["data"] = map[string]any{"flags": r.Flag, "tag": r.Tag, "value": r.Value}
		case *zonefile.URI:
			body["data"] = map[string]any{"target": r.Target, "weight": r.Weight}
		case *zonefile.SRV:
			body["data"] = map[string]any{"priority": r.Priority, "weight": r.Weight, "port": r.Port, "target": r.Target}
		}
	}
	return body, nil
}
func (c *Client) CreateZone(ctx context.Context, name string) (*dns.Zone, error) {
	name, err := dnsutil.ZoneName(name)
	if err != nil {
		return nil, err
	}
	account := c.accountID
	if account == "" {
		page, err := listDNS[struct {
			ID string `json:"id"`
		}](ctx, c, "/accounts", 1, map[string]string{})
		if err != nil {
			return nil, err
		}
		if page.Info.Total != 1 || len(page.Items) != 1 {
			return nil, errors.New("select a Cloudflare account ID to create the zone")
		}
		account = page.Items[0].ID
	}
	if !dnsID.MatchString(account) {
		return nil, ErrInvalidDNSRequest
	}
	res, err := dnsRequest[dns.Zone](ctx, c, http.MethodPost, "/zones", nil, map[string]any{"name": name, "account": map[string]string{"id": account}})
	if err != nil {
		return nil, err
	}
	if !dnsID.MatchString(res.Result.ID) || !strings.EqualFold(res.Result.Name, name) {
		return nil, ErrInvalidDNSRequest
	}
	return &res.Result, nil
}
