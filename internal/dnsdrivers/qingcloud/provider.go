// Package qingcloud manages individual RouteWize record values within their zone.
package qingcloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	sdk "github.com/certimate-go/certimate/pkg/sdk3rd/qingcloud/dns"
)

var errResponse = errors.New("invalid QingCloud DNS response")

type provider struct {
	key, secret string
	client      *http.Client
}

func New(a *domain.Access) (dns.Provider, error) {
	key, secret := dnsutil.Field(a, "accessKeyId"), dnsutil.Field(a, "secretAccessKey")
	if key == "" || secret == "" {
		return nil, domain.ErrInvalidParams
	}
	return &provider{key: key, secret: secret, client: dnsutil.HTTPClientFor(a)}, nil
}

func (p *provider) call(ctx context.Context, method, path string, q url.Values, input, out any) error {
	var body []byte
	if input != nil {
		var err error
		body, err = json.Marshal(input)
		if err != nil {
			return dns.ErrInvalidDNSRequest
		}
	}
	target := "https://api.routewize.com" + path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return dns.ErrInvalidDNSRequest
	}
	req.Header.Set("Content-Type", "application/json")
	if err = sdk.SignRequest(req, p.key, p.secret); err != nil {
		return errResponse
	}
	data, err := dnsutil.ReadResponse(p.client, req)
	if err != nil {
		return err
	}
	if len(data) == 0 && path == "/v1/zone/" {
		return nil
	}
	var status struct{ Code *int }
	if json.Unmarshal(data, &status) != nil || (status.Code == nil && path != "/v1/dns/host/") || (status.Code != nil && *status.Code != 0) {
		return errResponse
	}
	if out != nil && json.Unmarshal(data, out) != nil {
		return errResponse
	}
	return nil
}

func (p *provider) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	return p.zones(ctx, page, "")
}

func (p *provider) zones(ctx context.Context, page int, search string) (*dns.DNSPage[dns.Zone], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	offset := (page - 1) * dns.DNSPageSize
	var res struct {
		Zones []struct {
			Name   string `json:"zone_name"`
			Status string `json:"service_status"`
		} `json:"zones"`
		Total *int `json:"total_count"`
	}
	q := url.Values{"offset": {strconv.Itoa(offset)}, "limit": {strconv.Itoa(dns.DNSPageSize)}}
	if search != "" {
		q.Set("zone_name", search)
	}
	if err := p.call(ctx, "GET", "/v1/user/zones", q, nil, &res); err != nil {
		return nil, err
	}
	if !completePage(res.Total, offset, dns.DNSPageSize, len(res.Zones)) || res.Zones == nil {
		return nil, errResponse
	}
	result := dnsutil.Page[dns.Zone](page, *res.Total)
	for _, z := range res.Zones {
		name, err := dnsutil.ZoneName(z.Name)
		if err != nil {
			return nil, errResponse
		}
		result.Items = append(result.Items, dns.Zone{ID: name, Name: name, Status: z.Status})
	}
	return result, nil
}

func completePage(total *int, offset, limit, count int) bool {
	return total != nil && *total >= 0 && count == min(limit, max(0, *total-offset))
}

func (p *provider) CreateZone(ctx context.Context, name string) (*dns.Zone, error) {
	z, err := dnsutil.ZoneName(name)
	if err != nil {
		return nil, err
	}
	var res struct {
		Name string `json:"zone_name"`
	}
	if err = p.call(ctx, "POST", "/v1/zone/", nil, map[string]string{"zone_name": z}, &res); err != nil {
		return nil, err
	}
	if res.Name == "" {
		// A 204 acknowledgement does not carry an identifier. RouteWize's
		// zone filter is fuzzy, so only return an exact match on readback.
		for page := 1; ; page++ {
			result, err := p.zones(ctx, page, z)
			if err != nil {
				return nil, err
			}
			for _, item := range result.Items {
				if item.Name == z {
					return &item, nil
				}
			}
			if page*dns.DNSPageSize >= result.Info.Total {
				return nil, errResponse
			}
		}
	} else {
		actual, err := dnsutil.ZoneName(res.Name)
		if err != nil || actual != z {
			return nil, errResponse
		}
	}
	return &dns.Zone{ID: z, Name: z}, nil
}

func (p *provider) ZoneDetails(ctx context.Context, zone string) (*dns.ZoneDetails, error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return nil, err
	}
	var res struct {
		Name  string `json:"zone_name"`
		Lines []struct {
			ID   *int   `json:"id"`
			Name string `json:"name"`
		} `json:"zone_views"`
	}
	q := url.Values{"zone_name": {z + "."}, "action": {"GET_FULL"}, "type": {"GET_FULL"}}
	if err = p.call(ctx, "GET", "/v1/zone/view/", q, nil, &res); err != nil {
		return nil, err
	}
	name, err := dnsutil.ZoneName(res.Name)
	if err != nil || name != z || res.Lines == nil {
		return nil, errResponse
	}
	out := &dns.ZoneDetails{Name: z, MinTTL: 60, Lines: []dns.RecordLine{}}
	for _, line := range res.Lines {
		if line.ID == nil || *line.ID < 0 || line.Name == "" {
			return nil, errResponse
		}
		out.Lines = append(out.Lines, dns.RecordLine{ID: strconv.Itoa(*line.ID), Name: line.Name})
	}
	return out, nil
}

type value struct {
	ID     int64   `json:"record_value_id"`
	Value  *string `json:"value"`
	Status int     `json:"status"`
}
type group struct {
	Weight *int    `json:"weight"`
	Status int     `json:"group_status"`
	Values []value `json:"data"`
}
type record struct {
	ID     int64   `json:"domain_record_id"`
	Name   string  `json:"domain_name"`
	Zone   string  `json:"zone_name"`
	Type   string  `json:"rd_type"`
	Mode   int     `json:"mode"`
	Line   *int    `json:"view_id"`
	TTL    int     `json:"ttl"`
	Groups []group `json:"record"`
}

// Reject incomplete provider snapshots before using them to replace a record set.
func (r record) validate(zone string) error {
	actual, err := dnsutil.ZoneName(r.Zone)
	if err != nil || actual != zone {
		return domain.ErrRecordNotFound
	}
	if _, err = dnsutil.RelativeName(r.Name, zone); err != nil {
		return errResponse
	}
	if r.ID <= 0 || r.Type == "" || r.TTL <= 0 || r.Line == nil || *r.Line < 0 || r.Mode < 1 || r.Mode > 4 || len(r.Groups) == 0 {
		return errResponse
	}
	seen := make(map[int64]bool)
	for _, g := range r.Groups {
		if len(g.Values) == 0 || g.Weight == nil || *g.Weight < 0 || (g.Status != 1 && g.Status != 2) {
			return errResponse
		}
		for _, v := range g.Values {
			if v.ID <= 0 || seen[v.ID] || v.Value == nil || (v.Status != 1 && v.Status != 2) {
				return errResponse
			}
			seen[v.ID] = true
		}
	}
	return nil
}

func key(rid, vid int64) string { return strconv.FormatInt(rid, 10) + "_" + strconv.FormatInt(vid, 10) }

func row(r record, g group, v value) (dns.DNSRecord, error) {
	content := *v.Value
	d := dns.DNSRecord{ID: key(r.ID, v.ID), Name: strings.TrimSuffix(r.Name, "."), Type: r.Type, Line: strconv.Itoa(*r.Line), TTL: r.TTL, Status: "enabled"}
	if v.Status == 2 {
		d.Status = "disabled"
	}
	if r.Mode == 3 {
		d.Weight = g.Weight
	}
	if r.Type == "MX" {
		parts := strings.Fields(content)
		if len(parts) != 2 {
			return d, errResponse
		}
		n, err := strconv.Atoi(parts[0])
		if err != nil || n < 0 || n > 65535 {
			return d, errResponse
		}
		d.Priority = &n
		content = parts[1]
	}
	if r.Type == "TXT" && strings.HasPrefix(content, "\"") {
		if s, err := strconv.Unquote(content); err == nil {
			content = s
		}
	}
	d.Content = content
	return d, nil
}

func (p *provider) hostRecords(ctx context.Context, z, host string) ([]dns.DNSRecord, error) {
	var res struct {
		Records []record
		Total   *int `json:"total_count"`
	}
	q := url.Values{"zone_name": {z + "."}, "domain_name": {host + "."}}
	if err := p.call(ctx, "GET", "/v1/dns/host_info/", q, nil, &res); err != nil {
		return nil, err
	}
	if res.Total == nil || *res.Total != len(res.Records) || res.Records == nil {
		return nil, errResponse
	}
	var rows []dns.DNSRecord
	for _, r := range res.Records {
		if err := r.validate(z); err != nil {
			return nil, err
		}
		if !strings.EqualFold(strings.TrimSuffix(r.Name, "."), host) {
			return nil, errResponse
		}
		for _, g := range r.Groups {
			for _, v := range g.Values {
				d, err := row(r, g, v)
				if err != nil {
					return nil, err
				}
				rows = append(rows, d)
			}
		}
	}
	return rows, nil
}

func (p *provider) DNSRecords(ctx context.Context, zone string, page int, filter string) (*dns.DNSPage[dns.DNSRecord], error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil || !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	if filter != "" {
		if rel, err := dnsutil.RelativeName(filter, z); err == nil {
			rows, err := p.hostRecords(ctx, z, dnsutil.FullName(rel, z))
			if err != nil {
				return nil, err
			}
			return dnsutil.SlicePage(rows, page)
		}
	}
	rows, err := p.searchRecords(ctx, z, filter)
	if err != nil {
		return nil, err
	}
	return dnsutil.SlicePage(rows, page)
}

func (p *provider) searchRecords(ctx context.Context, z, filter string) ([]dns.DNSRecord, error) {
	// Host pagination counts names, whereas consumers page through individual values.
	const limit = 100
	seen := make(map[string]bool)
	rows := []dns.DNSRecord{}
	total := -1
	for offset := 0; ; offset += limit {
		var res struct {
			Hosts []struct {
				Name string `json:"domain_name"`
				Zone string `json:"zone_name"`
			} `json:"domains"`
			Total *int `json:"total_count"`
		}
		q := url.Values{"zone_name": {z + "."}, "offset": {strconv.Itoa(offset)}, "limit": {strconv.Itoa(limit)}}
		if filter != "" {
			q.Set("domain_name", filter)
		}
		if err := p.call(ctx, "GET", "/v1/dns/host/", q, nil, &res); err != nil {
			return nil, err
		}
		if res.Hosts == nil || !completePage(res.Total, offset, limit, len(res.Hosts)) || *res.Total > 20000 || (total >= 0 && total != *res.Total) {
			return nil, errResponse
		}
		total = *res.Total
		for _, host := range res.Hosts {
			h := strings.ToLower(strings.TrimSuffix(host.Name, "."))
			actual, err := dnsutil.ZoneName(host.Zone)
			if err != nil || actual != z || seen[h] {
				return nil, errResponse
			}
			if _, err = dnsutil.RelativeName(h, z); err != nil {
				return nil, errResponse
			}
			seen[h] = true
			part, err := p.hostRecords(ctx, z, h)
			if err != nil {
				return nil, err
			}
			if len(rows)+len(part) > 20000 {
				return nil, errResponse
			}
			rows = append(rows, part...)
		}
		if offset+len(res.Hosts) >= total {
			break
		}
	}
	return rows, nil
}
