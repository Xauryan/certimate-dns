package dnsmanagement

import (
	"context"
	"strconv"
	"strings"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	tc "github.com/go-acme/tencentclouddnspod/v20210323"
)

func (p *Tencent) ZoneDetails(ctx context.Context, zone string) (*dns.ZoneDetails, error) {
	z, err := zoneName(zone)
	if err != nil {
		return nil, err
	}
	req := tc.NewDescribeDomainRequest()
	req.Domain = &z
	r, err := tc.DescribeDomainWithContext(ctx, p.sdk, req)
	if err != nil || r == nil || r.Response == nil || r.Response.DomainInfo == nil {
		return nil, providerError("DNSPod")
	}
	d := r.Response.DomainInfo
	if !strings.EqualFold(val(d.Domain), z) && !strings.EqualFold(val(d.Punycode), z) {
		return nil, domain.ErrRecordNotFound
	}
	out := &dns.ZoneDetails{Name: z, Plan: val(d.GradeTitle), Status: val(d.Status), MinTTL: int(val(d.TTL))}
	for _, n := range d.DnspodNsList {
		if n != nil {
			out.Nameservers = append(out.Nameservers, *n)
		}
	}
	lines := tc.NewDescribeRecordLineCategoryListRequest()
	lines.Domain = &z
	v, err := tc.DescribeRecordLineCategoryListWithContext(ctx, p.sdk, lines)
	if err == nil && v != nil && v.Response != nil {
		out.Lines = tencentLines(v.Response.LineList)
		return out, nil
	}
	g := tc.NewDescribeRecordLineListRequest()
	g.Domain = &z
	g.DomainGrade = d.Grade
	fallback, err := tc.DescribeRecordLineListWithContext(ctx, p.sdk, g)
	if err != nil || fallback == nil || fallback.Response == nil {
		return nil, providerError("DNSPod")
	}
	for _, l := range fallback.Response.LineList {
		if l != nil {
			out.Lines = append(out.Lines, dns.RecordLine{ID: val(l.LineId), Name: val(l.Name)})
		}
	}
	for _, l := range fallback.Response.LineGroupList {
		if l != nil {
			out.Lines = append(out.Lines, dns.RecordLine{ID: val(l.LineId), Name: val(l.Name)})
		}
	}
	return out, nil
}

func tencentLines(list []*tc.LineItem) []dns.RecordLine {
	out := []dns.RecordLine{}
	seen := map[string]bool{}
	var walk func([]*tc.LineItem, string)
	walk = func(items []*tc.LineItem, parent string) {
		for _, item := range items {
			if item == nil {
				continue
			}
			nextParent := parent
			if val(item.Useful) {
				id := val(item.LineId)
				if id == "" {
					id = "N." + val(item.LineName)
				}
				if !seen[id] {
					out = append(out, dns.RecordLine{ID: id, Name: val(item.LineName), Parent: parent})
					seen[id] = true
				}
				nextParent = id
			}
			walk(item.SubGroup, nextParent)
		}
	}
	walk(list, "")
	return out
}

func (p *Tencent) DomainAliases(ctx context.Context, zone string) ([]dns.DomainAlias, error) {
	z, err := zoneName(zone)
	if err != nil {
		return nil, err
	}
	req := tc.NewDescribeDomainAliasListRequest()
	req.Domain = &z
	r, err := tc.DescribeDomainAliasListWithContext(ctx, p.sdk, req)
	if err != nil || r == nil || r.Response == nil {
		return nil, providerError("DNSPod")
	}
	out := []dns.DomainAlias{}
	for _, a := range r.Response.DomainAliasList {
		if a != nil && val(a.Id) > 0 {
			out = append(out, dns.DomainAlias{ID: strconv.FormatInt(*a.Id, 10), Name: val(a.DomainAlias)})
		}
	}
	return out, nil
}
func (p *Tencent) AddDomainAlias(ctx context.Context, zone, alias string) error {
	z, err := zoneName(zone)
	if err != nil {
		return err
	}
	name, err := zoneName(alias)
	if err != nil || name == z || !strings.Contains(name, ".") {
		return dns.ErrInvalidDNSRequest
	}
	req := tc.NewCreateDomainAliasRequest()
	req.Domain = &z
	req.DomainAlias = &name
	r, err := tc.CreateDomainAliasWithContext(ctx, p.sdk, req)
	if err != nil || r == nil || r.Response == nil || val(r.Response.DomainAliasId) <= 0 {
		return providerError("DNSPod")
	}
	return nil
}
func (p *Tencent) DeleteDomainAlias(ctx context.Context, zone, id string) error {
	z, err := zoneName(zone)
	if err != nil {
		return err
	}
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n < 1 {
		return dns.ErrInvalidDNSRequest
	}
	// Verify account-wide alias ID belongs to the selected domain before deletion.
	rows, err := p.DomainAliases(ctx, z)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.ID == id {
			req := tc.NewDeleteDomainAliasRequest()
			req.Domain = &z
			req.DomainAliasId = &n
			r, err := tc.DeleteDomainAliasWithContext(ctx, p.sdk, req)
			if err != nil || r == nil || r.Response == nil || val(r.Response.RequestId) == "" {
				return providerError("DNSPod")
			}
			return nil
		}
	}
	return domain.ErrRecordNotFound
}

func (p *Tencent) advancedRecord(ctx context.Context, z string, id uint64) (*tc.RecordInfo, error) {
	req := tc.NewDescribeRecordRequest()
	req.Domain = &z
	req.RecordId = &id
	r, err := tc.DescribeRecordWithContext(ctx, p.sdk, req)
	if err != nil || r == nil || r.Response == nil || r.Response.RecordInfo == nil {
		return nil, providerError("DNSPod")
	}
	if val(r.Response.RecordInfo.Id) != id {
		return nil, domain.ErrRecordNotFound
	}
	return r.Response.RecordInfo, nil
}
func (p *Tencent) BatchFields() []string { return []string{"status", "remark", "line", "weight"} }
func (p *Tencent) BatchAttribute(ctx context.Context, zone, id, field string) (string, error) {
	z, n, err := recordKey(zone, id)
	if err != nil {
		return "", err
	}
	b, err := p.advancedRecord(ctx, z, n)
	if err != nil {
		return "", err
	}
	switch field {
	case "status":
		if val(b.Enabled) == 1 {
			return "enabled", nil
		}
		return "disabled", nil
	case "remark":
		return val(b.Remark), nil
	case "line":
		if b.RecordLineId == nil || *b.RecordLineId == "" {
			return "N." + val(b.RecordLine), nil
		}
		return val(b.RecordLineId), nil
	case "weight":
		if b.Weight == nil {
			return "", nil
		}
		return strconv.FormatUint(*b.Weight, 10), nil
	}
	return "", dns.ErrInvalidDNSRequest
}
func (p *Tencent) SetBatchAttribute(ctx context.Context, zone, id, field, value string) error {
	z, n, err := recordKey(zone, id)
	if err != nil {
		return err
	}
	b, err := p.writableRecord(ctx, z, n)
	if err != nil {
		return err
	}
	switch field {
	case "remark":
		req := tc.NewModifyRecordRemarkRequest()
		req.Domain = &z
		req.RecordId = &n
		req.Remark = &value
		r, err := tc.ModifyRecordRemarkWithContext(ctx, p.sdk, req)
		if err == nil && r != nil && r.Response != nil && val(r.Response.RequestId) != "" {
			return nil
		}
	case "status":
		s, err := nativeStatus(value)
		if err != nil {
			return err
		}
		req := tc.NewModifyRecordStatusRequest()
		req.Domain = &z
		req.RecordId = &n
		req.Status = &s
		r, err := tc.ModifyRecordStatusWithContext(ctx, p.sdk, req)
		if err == nil && r != nil && r.Response != nil && val(r.Response.RecordId) == n {
			return nil
		}
	case "line", "weight":
		if b.Value == nil || b.TTL == nil || b.RecordLine == nil || (val(b.RecordType) == "MX" && b.MX == nil) {
			return providerError("DNSPod")
		}
		req := tc.NewModifyRecordRequest()
		req.Domain = &z
		req.RecordId = &n
		req.SubDomain = b.SubDomain
		req.RecordType = b.RecordType
		req.Value = b.Value
		req.TTL = b.TTL
		req.RecordLine = b.RecordLine
		req.RecordLineId = b.RecordLineId
		req.Remark = b.Remark
		req.Weight = b.Weight
		if val(b.RecordType) == "MX" {
			req.MX = b.MX
		}
		if b.Enabled != nil {
			req.Status = ptr("DISABLE")
			if *b.Enabled == 1 {
				req.Status = ptr("ENABLE")
			}
		}
		if field == "weight" {
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil || v > 100 {
				return dns.ErrInvalidDNSRequest
			}
			req.Weight = &v
		} else {
			info, err := p.ZoneDetails(ctx, z)
			if err != nil {
				return err
			}
			valid := false
			for _, l := range info.Lines {
				if l.ID == value {
					valid = true
					req.RecordLine = &l.Name
					if strings.HasPrefix(l.ID, "N.") {
						req.RecordLineId = nil
					} else {
						req.RecordLineId = &l.ID
					}
					break
				}
			}
			if !valid {
				return dns.ErrInvalidDNSRequest
			}
		}
		r, err := tc.ModifyRecordWithContext(ctx, p.sdk, req)
		if err == nil && r != nil && r.Response != nil && val(r.Response.RecordId) == n {
			return nil
		}
	default:
		return dns.ErrInvalidDNSRequest
	}
	return providerError("DNSPod")
}
