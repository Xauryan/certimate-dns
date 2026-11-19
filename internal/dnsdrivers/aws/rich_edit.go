package aws

import (
	"context"
	"reflect"
	"slices"
	"strings"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func recordRow(zone string, set types.ResourceRecordSet, value string) dns.DNSRecord {
	name := strings.ReplaceAll(strings.TrimSuffix(sdk.ToString(set.Name), "."), `\052`, "*")
	row := dns.DNSRecord{ID: recordID(zone, set, value), Name: name, Type: string(set.Type), Content: value, TTL: int(sdk.ToInt64(set.TTL)), Line: sdk.ToString(set.SetIdentifier), Status: "active", ReadOnly: readonly(set), Priority: dnsutil.MXPriority(string(set.Type), value)}
	if set.Weight != nil {
		weight := int(*set.Weight)
		row.Weight = &weight
	}
	return row
}
func (*provider) RecordEditCapabilities() dns.RecordEditCapabilities {
	return dns.RecordEditCapabilities{Rename: true, Retype: true, Priority: true, PresentationTXT: true}
}
func (p *provider) ReplaceDNSRecord(ctx context.Context, zone string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	source, idx, err := p.current(ctx, zone, prior.ID)
	if err != nil {
		return "", err
	}
	oldValue := sdk.ToString(source.ResourceRecords[idx].Value)
	if err = dnsutil.CheckReplacement("aws", prior, recordRow(zone, *source, oldValue), desired); err != nil {
		return "", err
	}
	info, err := p.ZoneDetails(ctx, zone)
	if err != nil {
		return "", err
	}
	label, err := dnsutil.RelativeName(desired.Name, info.Name)
	if err != nil {
		return "", err
	}
	if prior.Type == "NS" && strings.EqualFold(prior.Name, info.Name) || desired.Type == "NS" && label == "@" {
		return "", dns.ErrInvalidDNSRequest
	}
	name := strings.ReplaceAll(dnsutil.FullName(label, info.Name), "*", `\052`) + "."
	oldMX := ""
	if source.Type == types.RRTypeMx {
		oldMX = oldValue
	}
	value, err := dnsutil.MXValue(desired.Type, desired.Content, desired.Priority, oldMX)
	if err != nil {
		return "", err
	}
	target := *source
	target.Type = types.RRType(desired.Type)
	target.Name = &name
	target.TTL = sdk.Int64(int64(desired.TTL))
	value = rdata(target.Type, value)

	changes := []types.Change{{Action: types.ChangeActionDelete, ResourceRecordSet: source}}
	siblings := slices.Delete(slices.Clone(source.ResourceRecords), idx, idx+1)
	if strings.EqualFold(sdk.ToString(source.Name), name) && source.Type == target.Type {
		if len(siblings) > 0 && sdk.ToInt64(source.TTL) != int64(desired.TTL) {
			return "", dns.ErrInvalidDNSRequest
		}
		target.ResourceRecords = siblings
	} else {
		if len(siblings) > 0 {
			remainder := *source
			remainder.ResourceRecords = siblings
			changes = append(changes, types.Change{Action: types.ChangeActionCreate, ResourceRecordSet: &remainder})
		}
		// Only merge with an existing RRset when every routing attribute and
		// its TTL agree. DELETE uses the complete observed destination as a
		// precondition in the same transaction as the source changes.
		dst, err := p.find(ctx, key{Zone: zone, Name: name, Type: target.Type, Policy: sdk.ToString(target.SetIdentifier)})
		if err != nil {
			return "", err
		}
		target.ResourceRecords = nil
		if dst != nil {
			metadata := *dst
			metadata.ResourceRecords = nil
			metadata.Name = &name
			if !reflect.DeepEqual(metadata, target) {
				return "", dns.ErrInvalidDNSRequest
			}
			changes = append(changes, types.Change{Action: types.ChangeActionDelete, ResourceRecordSet: dst})
			target.ResourceRecords = slices.Clone(dst.ResourceRecords)
		}
	}
	for _, sibling := range target.ResourceRecords {
		if sdk.ToString(sibling.Value) == value {
			return "", dns.ErrInvalidDNSRequest
		}
	}
	target.ResourceRecords = append(target.ResourceRecords, types.ResourceRecord{Value: &value})
	changes = append(changes, types.Change{Action: types.ChangeActionCreate, ResourceRecordSet: &target})
	if err = p.commitChanges(ctx, zone, changes); err != nil {
		return "", err
	}
	return recordID(zone, target, value), nil
}
