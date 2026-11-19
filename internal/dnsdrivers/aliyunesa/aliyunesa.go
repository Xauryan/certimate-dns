// Package aliyunesa manages Alibaba Cloud ESA authoritative DNS sites.
package aliyunesa

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	esa "github.com/alibabacloud-go/esa-20240910/v3/client"
	"github.com/alibabacloud-go/tea/dara"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/dnsdrivers/registrarutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

var (
	errProvider   = errors.New("Alibaba Cloud ESA DNS request failed")
	regionPattern = regexp.MustCompile("^[a-z0-9]+(-[a-z0-9]+)+$")
)

type provider struct {
	sdk   *esa.Client
	group string
}

func New(a *domain.Access) (dns.Provider, error) {
	id, secret := dnsutil.Field(a, "accessKeyId"), dnsutil.Field(a, "accessKeySecret")
	if a == nil {
		return nil, domain.ErrInvalidParams
	}
	for _, field := range []string{"region", "resourceGroupId"} {
		if v, ok := a.Config[field]; ok && v != nil {
			if _, valid := v.(string); !valid {
				return nil, domain.ErrInvalidParams
			}
		}
	}
	region := dnsutil.Field(a, "region")
	if region == "" {
		region = "cn-hangzhou"
	}
	if strings.TrimSpace(id) == "" || strings.TrimSpace(secret) == "" || len(region) > 48 || !regionPattern.MatchString(region) {
		return nil, domain.ErrInvalidParams
	}
	client, err := esa.NewClient(&openapi.Config{
		AccessKeyId: &id, AccessKeySecret: &secret, RegionId: &region,
		Endpoint:   dara.String("esa." + region + ".aliyuncs.com"),
		HttpClient: dnsutil.AlibabaHTTPClient{Client: dnsutil.HTTPClientFor(a)},
	})
	if err != nil {
		return nil, errProvider
	}
	return &provider{client, dnsutil.Field(a, "resourceGroupId")}, nil
}

func sdkError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errProvider
}

func (p *provider) inScope(accessType, group *string) bool {
	return strings.EqualFold(dara.StringValue(accessType), "NS") && (p.group == "" || dara.StringValue(group) == p.group)
}

func completePage(page int, returnedPage, returnedSize, total *int32, count int) bool {
	if total == nil || *total < 0 || returnedPage != nil && int(*returnedPage) != page || returnedSize != nil && *returnedSize != dns.DNSPageSize {
		return false
	}
	return count == min(dns.DNSPageSize, max(0, int(*total)-(page-1)*dns.DNSPageSize))
}

func (p *provider) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	req := &esa.ListSitesRequest{AccessType: dara.String("NS"), PageNumber: dara.Int32(int32(page)), PageSize: dara.Int32(dns.DNSPageSize)}
	if p.group != "" {
		req.ResourceGroupId = &p.group
	}
	res, err := p.sdk.ListSitesWithContext(ctx, req, &dara.RuntimeOptions{})
	if err != nil || res == nil || res.Body == nil || !completePage(page, res.Body.PageNumber, res.Body.PageSize, res.Body.TotalCount, len(res.Body.Sites)) {
		return nil, sdkError(ctx)
	}
	out := dnsutil.Page[dns.Zone](page, int(*res.Body.TotalCount))
	for _, site := range res.Body.Sites {
		if site == nil || dara.Int64Value(site.SiteId) < 1 || !p.inScope(site.AccessType, site.ResourceGroupId) {
			return nil, errProvider
		}
		z, err := dnsutil.ZoneName(dara.StringValue(site.SiteName))
		if err != nil {
			return nil, errProvider
		}
		out.Items = append(out.Items, dns.Zone{ID: strconv.FormatInt(*site.SiteId, 10), Name: z, Status: dara.StringValue(site.Status)})
	}
	return out, nil
}

type site struct {
	id                 int64
	name, status, plan string
}

func (p *provider) site(ctx context.Context, zone string) (site, error) {
	id, err := dnsutil.PositiveID(zone)
	if err != nil {
		return site{}, err
	}
	res, err := p.sdk.GetSiteWithContext(ctx, &esa.GetSiteRequest{SiteId: &id}, &dara.RuntimeOptions{})
	if err != nil || res == nil || res.Body == nil || res.Body.SiteModel == nil {
		return site{}, sdkError(ctx)
	}
	s := res.Body.SiteModel
	if dara.Int64Value(s.SiteId) != id || !p.inScope(s.AccessType, s.ResourceGroupId) {
		return site{}, domain.ErrRecordNotFound
	}
	name, err := dnsutil.ZoneName(dara.StringValue(s.SiteName))
	if err != nil {
		return site{}, errProvider
	}
	return site{id: id, name: name, status: dara.StringValue(s.Status), plan: dara.StringValue(s.PlanName)}, nil
}

func (p *provider) ZoneDetails(ctx context.Context, zone string) (*dns.ZoneDetails, error) {
	s, err := p.site(ctx, zone)
	if err != nil {
		return nil, err
	}
	return &dns.ZoneDetails{Name: s.name, Status: s.status, Plan: s.plan, MinTTL: 1, Lines: []dns.RecordLine{{ID: "0", Name: "仅 DNS"}, {ID: "1", Name: "已代理"}}}, nil
}

func (p *provider) DNSRecords(ctx context.Context, zone string, page int, filter string) (*dns.DNSPage[dns.DNSRecord], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	s, err := p.site(ctx, zone)
	if err != nil {
		return nil, err
	}
	req := &esa.ListRecordsRequest{SiteId: &s.id, PageNumber: dara.Int32(int32(page)), PageSize: dara.Int32(dns.DNSPageSize)}
	if filter != "" {
		host, err := dnsutil.RelativeName(filter, s.name)
		if err != nil {
			host, err = dnsutil.RelativeName(dnsutil.FullName(filter, s.name), s.name)
			if err != nil {
				return nil, err
			}
		}
		req.RecordName = dara.String(dnsutil.FullName(host, s.name))
	}
	res, err := p.sdk.ListRecordsWithContext(ctx, req, &dara.RuntimeOptions{})
	if err != nil || res == nil || res.Body == nil || !completePage(page, res.Body.PageNumber, res.Body.PageSize, res.Body.TotalCount, len(res.Body.Records)) {
		return nil, sdkError(ctx)
	}
	out := dnsutil.Page[dns.DNSRecord](page, int(*res.Body.TotalCount))
	for _, r := range res.Body.Records {
		if r == nil || r.Data == nil || dara.Int64Value(r.RecordId) < 1 || dara.StringValue(r.RecordType) == "" || r.Ttl == nil || (r.SiteId != nil && *r.SiteId != s.id) {
			return nil, errProvider
		}
		if r.SiteName != nil && !strings.EqualFold(strings.TrimSuffix(*r.SiteName, "."), s.name) {
			return nil, errProvider
		}
		host, err := dnsutil.RelativeName(dara.StringValue(r.RecordName), s.name)
		if err != nil {
			return nil, errProvider
		}
		d := r.Data
		typ, content := dara.StringValue(r.RecordType), dara.StringValue(d.Value)
		switch typ {
		case "A/AAAA":
			if ip, err := netip.ParseAddr(content); err == nil {
				if ip.Is4() {
					typ = "A"
				} else {
					typ = "AAAA"
				}
			}
		case "CAA":
			if d.Flag == nil || d.Tag == nil || d.Value == nil {
				return nil, errProvider
			}
			content = registrarutil.FormatCAA(int(*d.Flag), *d.Tag, content)
		case "SRV":
			if d.Priority == nil || d.Weight == nil || d.Port == nil || d.Value == nil {
				return nil, errProvider
			}
			content = fmt.Sprintf("%d %d %d %s", dara.Int32Value(d.Priority), dara.Int32Value(d.Weight), dara.Int32Value(d.Port), content)
		case "MX":
			if d.Priority == nil || d.Value == nil {
				return nil, errProvider
			}
			content = fmt.Sprintf("%d %s", dara.Int32Value(d.Priority), content)
		}
		line := "0"
		if dara.BoolValue(r.Proxied) {
			line = "1"
		}
		rec := dns.DNSRecord{
			ID: strconv.FormatInt(*r.RecordId, 10), Name: dnsutil.FullName(host, s.name),
			Type: typ, Content: content, TTL: int(dara.Int64Value(r.Ttl)), Line: line,
			Proxied: dara.BoolValue(r.Proxied), Status: "active", Description: dara.StringValue(r.Comment),
		}
		if updated, err := time.Parse(time.RFC3339, dara.StringValue(r.UpdateTime)); err == nil {
			rec.UpdatedAt = updated.UTC().Format(time.RFC3339)
		}
		if d.Priority != nil {
			v := int(*d.Priority)
			rec.Priority = &v
		}
		if d.Weight != nil {
			v := int(*d.Weight)
			rec.Weight = &v
		}
		out.Items = append(out.Items, rec)
	}
	return out, nil
}

func validTTL(v int) bool { return v == 1 || v >= 30 && v <= 86400 }

// Complex record values use the same presentation on reads and writes.
func recordData(typ, value string) (*esa.CreateRecordRequestData, error) {
	if value == "" {
		return nil, dns.ErrInvalidDNSRequest
	}
	d := &esa.CreateRecordRequestData{Value: &value}
	switch typ {
	case "A", "AAAA", "A/AAAA":
		addresses := []string{value}
		if typ == "A/AAAA" {
			addresses = strings.Split(value, ",")
		}
		for _, address := range addresses {
			ip, err := netip.ParseAddr(address)
			if err != nil || ip.Zone() != "" || typ == "A" && !ip.Is4() || typ == "AAAA" && !ip.Is6() {
				return nil, dns.ErrInvalidDNSRequest
			}
		}
	case "CNAME", "TXT", "NS":
	case "MX":
		priority, target, err := registrarutil.ParseMX(value)
		if err != nil {
			return nil, err
		}
		d.Priority, d.Value = dara.Int32(int32(priority)), &target
	case "SRV":
		priority, weight, port, target, err := registrarutil.ParseSRV(value)
		if err != nil {
			return nil, err
		}
		d.Priority, d.Weight, d.Port, d.Value = dara.Int32(int32(priority)), dara.Int32(int32(weight)), dara.Int32(int32(port)), &target
	case "CAA":
		flag, tag, content, err := registrarutil.ParseCAA(value)
		if err != nil {
			return nil, err
		}
		d.Flag, d.Tag, d.Value = dara.Int32(int32(flag)), &tag, &content
	default:
		return nil, dns.ErrInvalidDNSRequest
	}
	return d, nil
}

func (p *provider) CreateDNSRecord(ctx context.Context, zone string, in dns.RecordInput) (string, error) {
	if !validTTL(in.TTL) {
		return "", dns.ErrInvalidDNSRequest
	}
	if (in.Weight != nil && in.Type != "SRV") || (in.Priority != nil && in.Type != "MX" && in.Type != "SRV") {
		return "", dns.ErrInvalidDNSRequest
	}
	content := in.Content
	if in.Type == "MX" {
		var err error
		content, err = dnsutil.MXValue(in.Type, content, in.Priority, "")
		if err != nil {
			return "", err
		}
	}
	data, err := recordData(in.Type, content)
	if err != nil {
		return "", err
	}
	if (in.Priority != nil && *in.Priority != int(dara.Int32Value(data.Priority))) || (in.Weight != nil && *in.Weight != int(dara.Int32Value(data.Weight))) {
		return "", dns.ErrInvalidDNSRequest
	}
	typ := in.Type
	if typ == "A" || typ == "AAAA" {
		typ = "A/AAAA"
	}
	proxied := in.Line == "1"
	switch in.Line {
	case "", "default", "0":
	case "1":
		if typ != "CNAME" && typ != "A/AAAA" {
			return "", dns.ErrInvalidDNSRequest
		}
	default:
		return "", dns.ErrInvalidDNSRequest
	}
	s, err := p.site(ctx, zone)
	if err != nil {
		return "", err
	}
	host, err := dnsutil.RelativeName(in.Name, s.name)
	if err != nil {
		return "", err
	}
	req := &esa.CreateRecordRequest{SiteId: &s.id, RecordName: dara.String(dnsutil.FullName(host, s.name)), Type: &typ, Data: data, Ttl: dara.Int32(int32(in.TTL)), Proxied: &proxied}
	if in.Description != "" {
		req.Comment = &in.Description
	}
	if proxied {
		req.BizName = dara.String("web")
	}
	res, err := p.sdk.CreateRecordWithContext(ctx, req, &dara.RuntimeOptions{})
	if err != nil || res == nil || res.Body == nil || dara.Int64Value(res.Body.RecordId) < 1 {
		return "", sdkError(ctx)
	}
	return strconv.FormatInt(*res.Body.RecordId, 10), nil
}

func (p *provider) record(ctx context.Context, zone, id string) (*esa.GetRecordResponseBodyRecordModel, error) {
	n, err := dnsutil.PositiveID(id)
	if err != nil {
		return nil, err
	}
	s, err := p.site(ctx, zone)
	if err != nil {
		return nil, err
	}
	res, err := p.sdk.GetRecordWithContext(ctx, &esa.GetRecordRequest{RecordId: &n}, &dara.RuntimeOptions{})
	if err != nil || res == nil || res.Body == nil || res.Body.RecordModel == nil {
		return nil, sdkError(ctx)
	}
	r := res.Body.RecordModel
	if dara.Int64Value(r.RecordId) != n || dara.Int64Value(r.SiteId) != s.id {
		return nil, domain.ErrRecordNotFound
	}
	if r.SiteName != nil && !strings.EqualFold(strings.TrimSuffix(*r.SiteName, "."), s.name) {
		return nil, domain.ErrRecordNotFound
	}
	if _, err = dnsutil.RelativeName(dara.StringValue(r.RecordName), s.name); err != nil {
		return nil, domain.ErrRecordNotFound
	}
	return r, nil
}

func (p *provider) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	if !validTTL(in.TTL) {
		return "", dns.ErrInvalidDNSRequest
	}
	r, err := p.record(ctx, zone, id)
	if err != nil {
		return "", err
	}
	if r.Data == nil || r.Data.Value == nil || len(r.Data.Tags) != 0 {
		return "", dns.ErrInvalidDNSRequest
	}
	typ := dara.StringValue(r.RecordType)
	if typ == "A/AAAA" {
		// A multi-address ESA record has a single native ID. Changing it from
		// an individual-address request would silently discard its other values.
		if strings.Contains(*r.Data.Value, ",") && !strings.Contains(in.Content, ",") {
			return "", dns.ErrInvalidDNSRequest
		}
		if prev, err := netip.ParseAddr(*r.Data.Value); err == nil {
			if prev.Is4() {
				typ = "A"
			} else {
				typ = "AAAA"
			}
		}
	}
	content := in.Content
	if typ == "MX" && !strings.Contains(content, " ") {
		if r.Data.Priority == nil {
			return "", errProvider
		}
		content = fmt.Sprintf("%d %s", *r.Data.Priority, content)
	}
	data, err := recordData(typ, content)
	if err != nil {
		return "", err
	}
	// UpdateRecord accepts sparse changes. Omitting origin/auth/proxy fields
	// preserves even settings whose values the read API has masked.
	req := &esa.UpdateRecordRequest{RecordId: r.RecordId, Ttl: dara.Int32(int32(in.TTL)), Data: &esa.UpdateRecordRequestData{
		Value: data.Value, Priority: data.Priority, Weight: data.Weight, Port: data.Port, Flag: data.Flag, Tag: data.Tag,
	}}
	if err := p.update(ctx, req); err != nil {
		return "", err
	}
	return id, nil
}

func (p *provider) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	r, err := p.record(ctx, zone, id)
	if err != nil {
		return "", err
	}
	res, err := p.sdk.DeleteRecordWithContext(ctx, &esa.DeleteRecordRequest{RecordId: r.RecordId}, &dara.RuntimeOptions{})
	if err != nil || res == nil || res.Body == nil || dara.StringValue(res.Body.RequestId) == "" {
		return "", sdkError(ctx)
	}
	return id, nil
}

func (p *provider) update(ctx context.Context, req *esa.UpdateRecordRequest) error {
	res, err := p.sdk.UpdateRecordWithContext(ctx, req, &dara.RuntimeOptions{})
	if err != nil || res == nil || res.Body == nil || dara.StringValue(res.Body.RequestId) == "" {
		return sdkError(ctx)
	}
	return nil
}

func (p *provider) BatchFields() []string { return []string{"line", "remark"} }

func (p *provider) BatchAttribute(ctx context.Context, zone, id, field string) (string, error) {
	r, err := p.record(ctx, zone, id)
	if err != nil {
		return "", err
	}
	switch field {
	case "line":
		if dara.BoolValue(r.Proxied) {
			return "1", nil
		}
		return "0", nil
	case "remark":
		return dara.StringValue(r.Comment), nil
	default:
		return "", dns.ErrInvalidDNSRequest
	}
}

func (p *provider) SetBatchAttribute(ctx context.Context, zone, id, field, value string) error {
	r, err := p.record(ctx, zone, id)
	if err != nil {
		return err
	}
	d := r.Data
	// ESA requires Data even for metadata-only changes. The update API
	// has no Tags field for HTTPS RDATA, so refuse a lossy round trip.
	if d == nil || len(d.Tags) != 0 {
		return dns.ErrInvalidDNSRequest
	}
	// Only round-trip metadata on record types whose required RDATA we can verify.
	switch dara.StringValue(r.RecordType) {
	case "A/AAAA", "CNAME", "NS", "TXT":
	case "MX":
		if d.Priority == nil {
			return errProvider
		}
	case "SRV":
		if d.Priority == nil || d.Weight == nil || d.Port == nil {
			return errProvider
		}
	case "CAA":
		if d.Flag == nil || d.Tag == nil {
			return errProvider
		}
	default:
		return dns.ErrInvalidDNSRequest
	}
	if d.Value == nil {
		return errProvider
	}
	req := &esa.UpdateRecordRequest{RecordId: r.RecordId, Data: &esa.UpdateRecordRequestData{
		Algorithm: d.Algorithm, Certificate: d.Certificate, Fingerprint: d.Fingerprint, Flag: d.Flag,
		KeyTag: d.KeyTag, MatchingType: d.MatchingType, Port: d.Port, Priority: d.Priority,
		Selector: d.Selector, Tag: d.Tag, Type: d.Type, Usage: d.Usage, Value: d.Value, Weight: d.Weight,
	}}
	switch field {
	case "line":
		typ := dara.StringValue(r.RecordType)
		if value != "0" && value != "1" || value == "1" && typ != "CNAME" && typ != "A/AAAA" {
			return dns.ErrInvalidDNSRequest
		}
		req.Proxied = dara.Bool(value == "1")
		if value == "1" {
			req.BizName = r.BizName
			if dara.StringValue(req.BizName) == "" {
				req.BizName = dara.String("web")
			}
		}
	case "remark":
		req.Comment = &value
	default:
		return dns.ErrInvalidDNSRequest
	}
	return p.update(ctx, req)
}
