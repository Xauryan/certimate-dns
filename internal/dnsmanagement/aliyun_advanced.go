package dnsmanagement

import (
	"context"
	"strconv"
	"strings"

	"github.com/alibabacloud-go/tea/dara"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	ali "github.com/go-acme/alidns-20150109/v5/client"
)

func (p *Aliyun) ZoneDetails(ctx context.Context, zone string) (*dns.ZoneDetails, error) {
	z, err := zoneName(zone)
	if err != nil {
		return nil, err
	}
	r, err := ali.DescribeDomainInfoWithContext(ctx, p.sdk, &ali.DescribeDomainInfoRequest{DomainName: &z, NeedDetailAttributes: ptr(true)}, &dara.RuntimeOptions{})
	if err != nil || r == nil || r.Body == nil {
		return nil, providerError("Aliyun")
	}
	b := r.Body
	if !strings.EqualFold(val(b.DomainName), z) || (p.group != "" && val(b.ResourceGroupId) != p.group) {
		return nil, domain.ErrRecordNotFound
	}
	out := &dns.ZoneDetails{Name: z, MinTTL: int(val(b.MinTtl)), Plan: val(b.VersionName)}
	if b.RecordLines != nil {
		for _, line := range b.RecordLines.RecordLine {
			if line != nil {
				out.Lines = append(out.Lines, dns.RecordLine{ID: val(line.LineCode), Name: val(line.LineDisplayName), Parent: val(line.FatherCode)})
			}
		}
	}
	if b.DnsServers != nil {
		for _, n := range b.DnsServers.DnsServer {
			if n != nil {
				out.Nameservers = append(out.Nameservers, *n)
			}
		}
	}
	return out, nil
}

func (p *Aliyun) BatchFields() []string { return []string{"status", "remark", "line", "weight"} }

func (p *Aliyun) BatchAttribute(ctx context.Context, zone, id, field string) (string, error) {
	b, err := p.record(ctx, zone, id)
	if err != nil {
		return "", err
	}
	switch field {
	case "status":
		switch val(b.Status) {
		case "ENABLE":
			return "enabled", nil
		case "DISABLE":
			return "disabled", nil
		}
	case "remark":
		return val(b.Remark), nil
	case "line":
		return val(b.Line), nil
	case "weight":
		// The record-detail API omits weight. Match the exact RR, type, line and value, then the record ID.
		for page := int64(1); page <= 100; page++ {
			req := &ali.DescribeDomainRecordsRequest{DomainName: b.DomainName, RRKeyWord: b.RR, Type: b.Type, Line: b.Line, ValueKeyWord: b.Value, SearchMode: ptr("COMBINATION"), PageNumber: &page, PageSize: ptr(int64(100))}
			r, err := ali.DescribeDomainRecordsWithContext(ctx, p.sdk, req, &dara.RuntimeOptions{})
			if err != nil || r == nil || r.Body == nil || r.Body.DomainRecords == nil {
				return "", providerError("Aliyun")
			}
			for _, row := range r.Body.DomainRecords.Record {
				if row != nil && val(row.RecordId) == id {
					if row.Weight == nil {
						return "", nil
					}
					return strconv.Itoa(int(*row.Weight)), nil
				}
			}
			if page*100 >= val(r.Body.TotalCount) {
				break
			}
		}
		return "", domain.ErrRecordNotFound
	}
	return "", dns.ErrInvalidDNSRequest
}

func nativeStatus(value string) (string, error) {
	switch value {
	case "enabled":
		return "ENABLE", nil
	case "disabled":
		return "DISABLE", nil
	}
	return "", dns.ErrInvalidDNSRequest
}
func (p *Aliyun) SetBatchAttribute(ctx context.Context, zone, id, field, value string) error {
	b, err := p.writableRecord(ctx, zone, id)
	if err != nil {
		return err
	}
	rt := &dara.RuntimeOptions{}
	switch field {
	case "status":
		status, err := nativeStatus(value)
		if err != nil {
			return err
		}
		r, err := ali.SetDomainRecordStatusWithContext(ctx, p.sdk, &ali.SetDomainRecordStatusRequest{RecordId: &id, Status: &status}, rt)
		if err == nil && r != nil && r.Body != nil && val(r.Body.RecordId) == id {
			return nil
		}
	case "remark":
		r, err := ali.UpdateDomainRecordRemarkWithContext(ctx, p.sdk, &ali.UpdateDomainRecordRemarkRequest{RecordId: &id, Remark: &value}, rt)
		if err == nil && r != nil && r.Body != nil && val(r.Body.RequestId) != "" {
			return nil
		}
	case "line":
		if b.RR == nil || b.Type == nil || b.Value == nil || b.TTL == nil || (val(b.Type) == "MX" && b.Priority == nil) {
			return providerError("Aliyun")
		}
		if strings.TrimSpace(value) == "" {
			return dns.ErrInvalidDNSRequest
		}
		req := &ali.UpdateDomainRecordRequest{RecordId: &id, RR: b.RR, Type: b.Type, Value: b.Value, TTL: b.TTL, Line: &value}
		if val(b.Type) == "MX" {
			req.Priority = b.Priority
		}
		r, err := ali.UpdateDomainRecordWithContext(ctx, p.sdk, req, rt)
		if err == nil && r != nil && r.Body != nil && val(r.Body.RecordId) == id {
			return nil
		}
	case "weight":
		n, err := strconv.ParseInt(value, 10, 32)
		if err != nil || n < 1 || n > 100 {
			return dns.ErrInvalidDNSRequest
		}
		r, err := ali.UpdateDNSSLBWeightWithContext(ctx, p.sdk, &ali.UpdateDNSSLBWeightRequest{RecordId: &id, Weight: ptr(int32(n))}, rt)
		if err == nil && r != nil && r.Body != nil && val(r.Body.RequestId) != "" {
			return nil
		}
	default:
		return dns.ErrInvalidDNSRequest
	}
	return providerError("Aliyun")
}

func (p *Aliyun) WeightRules(ctx context.Context, zone string, page int, search string) (*dns.DNSPage[dns.WeightRule], error) {
	z, err := p.zone(ctx, zone)
	if err != nil {
		return nil, err
	}
	req := &ali.DescribeDNSSLBSubDomainsRequest{DomainName: &z, PageNumber: ptr(int64(page)), PageSize: ptr(int64(dns.DNSPageSize))}
	if search != "" {
		req.Rr = &search
	}
	r, err := ali.DescribeDNSSLBSubDomainsWithContext(ctx, p.sdk, req, &dara.RuntimeOptions{})
	if err != nil || r == nil || r.Body == nil {
		return nil, providerError("Aliyun")
	}
	out := newPage[dns.WeightRule](page, int(val(r.Body.TotalCount)))
	if r.Body.SlbSubDomains != nil {
		for _, s := range r.Body.SlbSubDomains.SlbSubDomain {
			if s == nil {
				continue
			}
			base := dns.WeightRule{Name: val(s.SubDomain), Type: val(s.Type), Enabled: val(s.Open)}
			if s.LineAlgorithms == nil || len(s.LineAlgorithms.LineAlgorithm) == 0 {
				out.Items = append(out.Items, base)
				continue
			}
			for _, line := range s.LineAlgorithms.LineAlgorithm {
				if line != nil {
					row := base
					row.Line = val(line.Line)
					row.Enabled = val(line.Open)
					out.Items = append(out.Items, row)
				}
			}
		}
	}
	return out, nil
}

func (p *Aliyun) SetWeightRule(ctx context.Context, zone string, rule dns.WeightRule) error {
	z, err := p.zone(ctx, zone)
	if err != nil {
		return err
	}
	rr, err := relative(rule.Name, z)
	if err != nil || (rule.Type != "A" && rule.Type != "AAAA") {
		return dns.ErrInvalidDNSRequest
	}
	name := fullName(rr, z)
	req := &ali.SetDNSSLBStatusRequest{DomainName: &z, SubDomain: &name, Type: &rule.Type, Open: &rule.Enabled}
	if rule.Line != "" {
		req.Line = &rule.Line
	}
	r, err := ali.SetDNSSLBStatusWithContext(ctx, p.sdk, req, &dara.RuntimeOptions{})
	if err != nil || r == nil || r.Body == nil || val(r.Body.RequestId) == "" {
		return providerError("Aliyun")
	}
	return nil
}
