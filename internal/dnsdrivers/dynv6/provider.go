// Package dynv6 implements the DNS record operations of dynv6 REST API v2.
package dynv6

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/dnsdrivers/registrarutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	sdk "github.com/certimate-go/certimate/pkg/sdk3rd/dynv6"
)

type provider struct{ api registrarutil.API }

func New(a *domain.Access) (dns.Provider, error) {
	token := dnsutil.Field(a, "httpToken")
	if token == "" {
		return nil, domain.ErrInvalidParams
	}
	return &provider{registrarutil.API{Base: "https://dynv6.com/api/v2", Client: dnsutil.HTTPClientFor(a), Headers: http.Header{"Authorization": {"Bearer " + token}}}}, nil
}

func (p *provider) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	var rows []sdk.ZoneRecord
	if err := p.api.JSON(ctx, "GET", "/zones", nil, &rows); err != nil {
		return nil, err
	}
	if rows == nil {
		return nil, registrarutil.ErrInventory
	}
	zones := make([]dns.Zone, 0, len(rows))
	for _, row := range rows {
		if _, err := dnsutil.ZoneName(row.Name); row.ID <= 0 || err != nil {
			return nil, errors.New("invalid dynv6 zone response")
		}
		zones = append(zones, dns.Zone{ID: row.Name, Name: row.Name, Status: "active"})
	}
	return dnsutil.SlicePage(zones, page)
}

func (p *provider) recordsPath(ctx context.Context, zone string) (string, string, error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", "", err
	}
	var row sdk.ZoneRecord
	if err := p.api.JSON(ctx, "GET", "/zones/by-name/"+url.PathEscape(z), nil, &row); err != nil {
		return "", "", err
	}
	if row.ID <= 0 || !strings.EqualFold(row.Name, z) {
		return "", "", domain.ErrRecordNotFound
	}
	return fmt.Sprintf("/zones/%d/records", row.ID), z, nil
}

// Some API deployments return a single record as an object.
type recordList []sdk.DNSRecord

func (rows *recordList) UnmarshalJSON(data []byte) error {
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		var one sdk.DNSRecord
		if err := json.Unmarshal(data, &one); err != nil {
			return err
		}
		*rows = []sdk.DNSRecord{one}
		return nil
	}
	return json.Unmarshal(data, (*[]sdk.DNSRecord)(rows))
}

// dynv6 does not publish a configurable TTL. The source console uses 600 as its display value.
const displayTTL = 600

func (p *provider) DNSRecords(ctx context.Context, zone string, page int, filter string) (*dns.DNSPage[dns.DNSRecord], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	path, z, err := p.recordsPath(ctx, zone)
	if err != nil {
		return nil, err
	}
	var rows recordList
	if err := p.api.JSON(ctx, "GET", path, nil, &rows); err != nil {
		return nil, err
	}
	if rows == nil {
		return nil, registrarutil.ErrInventory
	}
	seen := map[int64]bool{}
	items := make([]dns.DNSRecord, 0, len(rows))
	for _, r := range rows {
		if seen[r.ID] || r.ID <= 0 || r.Type == "" || path != fmt.Sprintf("/zones/%d/records", r.ZoneID) {
			return nil, errors.New("invalid dynv6 record response")
		}
		seen[r.ID] = true
		name := strings.TrimSuffix(r.Name, ".")
		if _, err := dnsutil.RelativeName(name, z); err != nil || name == "@" {
			if strings.HasSuffix(r.Name, ".") {
				return nil, registrarutil.ErrInventory
			}
			name = dnsutil.FullName(name, z)
		}
		content := r.Data
		switch r.Type {
		case "SRV":
			content = fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, r.Data)
		case "MX":
			content = fmt.Sprintf("%d %s", r.Priority, r.Data)
		case "CAA":
			content = registrarutil.FormatCAA(r.Flags, r.Tag, r.Data)
		}
		if strings.Contains(strings.ToLower(name), strings.ToLower(filter)) {
			items = append(items, dns.DNSRecord{ID: strconv.FormatInt(r.ID, 10), Name: name, Type: r.Type, Priority: dnsutil.MXPriority(r.Type, content), Content: content, TTL: displayTTL, Line: "default", Status: "active"})
		}
	}
	return dnsutil.SlicePage(items, page)
}

func validWrite(typ string, ttl int) error {
	if ttl != displayTTL {
		return domain.NewError(400, "dynv6 manages TTL automatically (use 600)")
	}
	switch typ {
	case "A", "AAAA", "CNAME", "TXT", "SPF", "MX", "SRV", "CAA":
		return nil
	}
	return dns.ErrInvalidDNSRequest
}

func value(typ, content string) string {
	if (typ == "CNAME" || typ == "MX") && strings.Contains(content, ".") && !strings.HasSuffix(content, ".") {
		return content + "."
	}
	return content
}

func recordValue(typ, content string) (*sdk.AddRecordRequest, error) {
	if content == "" {
		return nil, dns.ErrInvalidDNSRequest
	}
	req := &sdk.AddRecordRequest{}
	switch typ {
	case "MX":
		priority, exchange, err := registrarutil.ParseMX(content)
		if err != nil {
			return nil, err
		}
		req.Priority = &priority
		content = exchange
	case "SRV":
		priority, weight, port, target, err := registrarutil.ParseSRV(content)
		if err != nil {
			return nil, err
		}
		req.Priority, req.Weight, req.Port = &priority, &weight, &port
		content = target
	case "CAA":
		flags, tag, v, err := registrarutil.ParseCAA(content)
		if err != nil {
			return nil, err
		}
		req.Flags, req.Tag = &flags, &tag
		content = v
	}
	data := value(typ, content)
	req.Data = &data
	return req, nil
}
func (p *provider) CreateDNSRecord(ctx context.Context, zone string, in dns.RecordInput) (string, error) {
	if in.Priority != nil && in.Type != "MX" || in.Description != "" || in.Weight != nil {
		return "", dns.ErrInvalidDNSRequest
	}
	if err := validWrite(in.Type, in.TTL); err != nil {
		return "", err
	}
	path, z, err := p.recordsPath(ctx, zone)
	if err != nil {
		return "", err
	}
	host, err := dnsutil.RelativeName(in.Name, z)
	if err != nil {
		return "", err
	}
	if host == "@" {
		host = z
	}
	if in.Line != "" && in.Line != "default" {
		return "", dns.ErrInvalidDNSRequest
	}
	if in.Type == "MX" {
		in.Content, err = dnsutil.MXValue(in.Type, in.Content, in.Priority, "")
		if err != nil {
			return "", err
		}
	}
	req, err := recordValue(in.Type, in.Content)
	if err != nil {
		return "", err
	}
	req.Name = &host
	req.Type = &in.Type
	var result sdk.DNSRecord
	if err := p.api.JSON(ctx, "POST", path, req, &result); err != nil {
		return "", err
	}
	if result.ID <= 0 {
		return "", errors.New("dynv6 returned no record ID")
	}
	return strconv.FormatInt(result.ID, 10), nil
}

func (p *provider) record(ctx context.Context, zone, id string) (string, *sdk.DNSRecord, error) {
	n, err := dnsutil.PositiveID(id)
	if err != nil {
		return "", nil, dns.ErrInvalidDNSRequest
	}
	path, _, err := p.recordsPath(ctx, zone)
	if err != nil {
		return "", nil, err
	}
	path += "/" + strconv.FormatInt(n, 10)
	var row sdk.DNSRecord
	if err := p.api.JSON(ctx, "GET", path, nil, &row); err != nil {
		return "", nil, err
	}
	if row.Type == "" || row.ID != n || !strings.HasPrefix(path, fmt.Sprintf("/zones/%d/", row.ZoneID)) {
		return "", nil, domain.ErrRecordNotFound
	}
	return path, &row, nil
}

func (p *provider) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	path, row, err := p.record(ctx, zone, id)
	if err != nil {
		return "", err
	}
	if err := validWrite(row.Type, in.TTL); err != nil {
		return "", err
	}
	in.Content, err = dnsutil.MXValue(row.Type, in.Content, nil, strconv.Itoa(row.Priority)+" "+row.Data)
	if err != nil {
		return "", err
	}
	req, err := recordValue(row.Type, in.Content)
	if err != nil {
		return "", err
	}
	if err := p.api.JSON(ctx, "PATCH", path, req, nil); err != nil {
		return "", err
	}
	return id, nil
}

func (p *provider) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	path, _, err := p.record(ctx, zone, id)
	if err != nil {
		return "", err
	}
	if err := p.api.JSON(ctx, "DELETE", path, nil, nil); err != nil {
		return "", err
	}
	return id, nil
}
