package huawei

import (
	"context"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func (*provider) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true, PresentationTXT: true}
}

func (p *provider) ReplaceDNSRecord(ctx context.Context, zone string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	r, err := p.current(ctx, zone, prior.ID)
	if err != nil {
		return "", err
	}
	if err = dnsutil.CheckReplacement("huaweicloud", prior, r.row(), desired); err != nil {
		return "", err
	}
	// Name and type belong to the whole RRset. The single-record editor
	// cannot move one answer out of a multi-value set in one Huawei request.
	if len(r.Records) != 1 || strings.ContainsAny(desired.Content, "\r\n") {
		return "", dns.ErrInvalidDNSRequest
	}
	label, err := dnsutil.RelativeName(desired.Name, r.ZoneName)
	if err != nil {
		return "", err
	}
	previous := ""
	if r.Type == "MX" {
		previous = r.Records[0]
	}
	content, err := dnsutil.MXValue(desired.Type, desired.Content, desired.Priority, previous)
	if err != nil {
		return "", err
	}
	r.Name = dnsutil.FullName(label, r.ZoneName) + "."
	r.Type = desired.Type
	return p.update(ctx, r, map[string]any{"records": []string{rdata(r.Type, content)}, "ttl": desired.TTL})
}
