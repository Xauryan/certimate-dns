// Package aws manages Route 53 hosted zones and record sets.
package aws

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"

	"strings"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

var failure = errors.New("Route 53 DNS request failed; refresh before retrying a change")
var zoneID = regexp.MustCompile("^[a-zA-Z0-9]{1,64}$")

type provider struct{ client *route53.Client }

func New(a *domain.Access) (dns.Provider, error) {
	if a == nil {
		return nil, domain.ErrInvalidParams
	}
	var auth sdk.CredentialsProvider
	id, secret := dnsutil.Field(a, "accessKeyId"), dnsutil.Field(a, "secretAccessKey")
	switch dnsutil.Field(a, "authMethod") {
	case "", "accesskey":
		if id == "" || secret == "" {
			return nil, domain.ErrInvalidParams
		}
		auth = credentials.NewStaticCredentialsProvider(id, secret, "")
	case "imds":
		// Instance metadata stays on the instance's network. The account's
		// proxy applies to Route 53 API calls only.
		metadataHTTP := awshttp.NewBuildableClient().WithTransportOptions(func(t *http.Transport) { t.Proxy = nil })
		auth = sdk.NewCredentialsCache(ec2rolecreds.New(func(o *ec2rolecreds.Options) {
			o.Client = imds.New(imds.Options{HTTPClient: metadataHTTP})
		}))
	default:
		return nil, domain.ErrInvalidParams
	}
	client := route53.New(route53.Options{Credentials: auth, Region: "us-east-1", HTTPClient: dnsutil.HTTPClientFor(a), RetryMaxAttempts: 1})
	return &provider{client}, nil
}

func (p *provider) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	var zones []dns.Zone
	in := &route53.ListHostedZonesInput{}
	seen := map[string]bool{}
	for {
		out, err := p.client.ListHostedZones(ctx, in)
		if err != nil {
			return nil, failure
		}
		for _, z := range out.HostedZones {
			id := strings.TrimPrefix(sdk.ToString(z.Id), "/hostedzone/")
			name, e := dnsutil.ZoneName(sdk.ToString(z.Name))
			if !zoneID.MatchString(id) || e != nil {
				return nil, failure
			}
			zones = append(zones, dns.Zone{ID: id, Name: name, Status: "active"})
		}
		if !out.IsTruncated {
			break
		}
		key := sdk.ToString(out.NextMarker)
		if key == "" || seen[key] {
			return nil, failure
		}
		seen[key] = true
		in.Marker = out.NextMarker
	}
	return dnsutil.SlicePage(zones, page)
}

// Route 53 has no per-value ID. Include the seek key for efficient lookups and
// a digest of the original RDATA so stale values cannot select a sibling.
type key struct {
	Zone   string       `json:"z"`
	Name   string       `json:"n"`
	Type   types.RRType `json:"t"`
	Policy string       `json:"p,omitempty"`
	Digest string       `json:"v"`
}

func recordID(zone string, set types.ResourceRecordSet, value string) string {
	digest := sha256.Sum256([]byte(value))
	data, _ := json.Marshal(key{zone, sdk.ToString(set.Name), set.Type, sdk.ToString(set.SetIdentifier), base64.RawURLEncoding.EncodeToString(digest[:])})
	return base64.RawURLEncoding.EncodeToString(data)
}

func readonly(set types.ResourceRecordSet) bool {
	return set.Type == types.RRTypeSoa || set.AliasTarget != nil || set.TrafficPolicyInstanceId != nil
}

func completeSet(set types.ResourceRecordSet) bool {
	if sdk.ToString(set.Name) == "" || set.Type == "" {
		return false
	}
	if set.AliasTarget != nil {
		return sdk.ToString(set.AliasTarget.DNSName) != ""
	}
	if set.TTL == nil || len(set.ResourceRecords) == 0 {
		return false
	}
	for _, rr := range set.ResourceRecords {
		if sdk.ToString(rr.Value) == "" {
			return false
		}
	}
	return true
}

func (p *provider) DNSRecords(ctx context.Context, zone string, page int, filter string) (*dns.DNSPage[dns.DNSRecord], error) {
	if !dnsutil.ValidPage(page) || !zoneID.MatchString(zone) {
		return nil, dns.ErrInvalidDNSRequest
	}
	var rows []dns.DNSRecord
	in := &route53.ListResourceRecordSetsInput{HostedZoneId: &zone}
	seen := map[[3]string]bool{}
	for {
		out, err := p.client.ListResourceRecordSets(ctx, in)
		if err != nil {
			return nil, failure
		}
		for _, set := range out.ResourceRecordSets {
			if !completeSet(set) {
				return nil, failure
			}
			if set.AliasTarget != nil {
				row := recordRow(zone, set, sdk.ToString(set.AliasTarget.DNSName))
				if strings.Contains(strings.ToLower(row.Name), strings.ToLower(filter)) {
					rows = append(rows, row)
				}
				continue
			}
			for _, rr := range set.ResourceRecords {
				row := recordRow(zone, set, sdk.ToString(rr.Value))
				if strings.Contains(strings.ToLower(row.Name), strings.ToLower(filter)) {
					rows = append(rows, row)
				}
			}
		}
		if !out.IsTruncated {
			break
		}
		token := [3]string{sdk.ToString(out.NextRecordName), string(out.NextRecordType), sdk.ToString(out.NextRecordIdentifier)}
		if token[0] == "" || token[1] == "" || seen[token] {
			return nil, failure
		}
		seen[token] = true
		in.StartRecordName, in.StartRecordType, in.StartRecordIdentifier = out.NextRecordName, out.NextRecordType, out.NextRecordIdentifier
	}
	return dnsutil.SlicePage(rows, page)
}

func (p *provider) find(ctx context.Context, k key) (*types.ResourceRecordSet, error) {
	req := &route53.ListResourceRecordSetsInput{HostedZoneId: &k.Zone, StartRecordName: &k.Name, StartRecordType: k.Type, MaxItems: sdk.Int32(1)}
	if k.Policy != "" {
		req.StartRecordIdentifier = &k.Policy
	}
	out, err := p.client.ListResourceRecordSets(ctx, req)
	if err != nil {
		return nil, failure
	}
	if len(out.ResourceRecordSets) == 0 {
		return nil, nil
	}
	set := out.ResourceRecordSets[0]
	if !completeSet(set) {
		return nil, failure
	}
	if !strings.EqualFold(sdk.ToString(set.Name), k.Name) || set.Type != k.Type || sdk.ToString(set.SetIdentifier) != k.Policy {
		return nil, nil
	}
	return &set, nil
}

// Compare-and-swap the complete old RRset in a single transactional batch.
// A concurrent modification causes DELETE to fail, leaving both changes unapplied.
func (p *provider) change(ctx context.Context, zone string, old, next *types.ResourceRecordSet) error {
	var changes []types.Change
	if old != nil {
		changes = append(changes, types.Change{Action: types.ChangeActionDelete, ResourceRecordSet: old})
	}
	if next != nil {
		changes = append(changes, types.Change{Action: types.ChangeActionCreate, ResourceRecordSet: next})
	}
	return p.commitChanges(ctx, zone, changes)
}
func (p *provider) commitChanges(ctx context.Context, zone string, changes []types.Change) error {
	_, err := p.client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{HostedZoneId: &zone, ChangeBatch: &types.ChangeBatch{Changes: changes}})
	if err != nil {
		return failure
	}
	return nil
}

func rdata(typ types.RRType, value string) string {
	if typ == types.RRTypeTxt {
		return dns.QuoteRecordTXT(value)
	}
	return value
}

func (p *provider) CreateDNSRecord(ctx context.Context, zone string, in dns.RecordInput) (string, error) {
	if in.Type == "SOA" || !zoneID.MatchString(zone) || (in.Line != "" && in.Line != "default") || in.Type == "" || in.TTL < 1 || in.Content == "" {
		return "", dns.ErrInvalidDNSRequest
	}
	info, err := p.ZoneDetails(ctx, zone)
	if err != nil {
		return "", err
	}
	z := info.Name
	rr, err := dnsutil.RelativeName(in.Name, z)
	if err != nil {
		return "", err
	}
	name := strings.ReplaceAll(dnsutil.FullName(rr, z), "*", `\052`) + "."
	if in.Description != "" || in.Weight != nil {
		return "", dns.ErrInvalidDNSRequest
	}
	in.Content, err = dnsutil.MXValue(in.Type, in.Content, in.Priority, "")
	if err != nil {
		return "", err
	}
	typ := types.RRType(in.Type)
	old, err := p.find(ctx, key{Zone: zone, Name: name, Type: typ})
	if err != nil {
		return "", err
	}
	set := types.ResourceRecordSet{Name: &name, Type: typ, TTL: sdk.Int64(int64(in.TTL))}
	value := rdata(typ, in.Content)
	if old != nil {
		// TTL belongs to the whole set. Adding one answer must not change its siblings' TTL.
		if readonly(*old) || sdk.ToInt64(old.TTL) != int64(in.TTL) {
			return "", dns.ErrInvalidDNSRequest
		}
		set = *old
		set.ResourceRecords = slices.Clone(old.ResourceRecords)
		for _, r := range set.ResourceRecords {
			if sdk.ToString(r.Value) == value {
				return "", dns.ErrInvalidDNSRequest
			}
		}
	}
	set.ResourceRecords = append(set.ResourceRecords, types.ResourceRecord{Value: &value})
	if err := p.change(ctx, zone, old, &set); err != nil {
		return "", err
	}
	return recordID(zone, set, value), nil
}

func (p *provider) current(ctx context.Context, zone, id string) (*types.ResourceRecordSet, int, error) {
	if !zoneID.MatchString(zone) || len(id) > 4096 {
		return nil, 0, dns.ErrInvalidDNSRequest
	}
	data, err := base64.RawURLEncoding.DecodeString(id)
	var k key
	if err != nil || json.Unmarshal(data, &k) != nil || k.Name == "" || k.Type == "" {
		return nil, 0, dns.ErrInvalidDNSRequest
	}
	if k.Zone != zone {
		return nil, 0, domain.ErrRecordNotFound
	}
	set, err := p.find(ctx, k)
	if err != nil {
		return nil, 0, err
	}
	if set != nil {
		if readonly(*set) {
			return nil, 0, dns.ErrInvalidDNSRequest
		}
		for i, r := range set.ResourceRecords {
			if recordID(zone, *set, sdk.ToString(r.Value)) == id {
				return set, i, nil
			}
		}
	}
	return nil, 0, domain.ErrRecordNotFound
}

func (p *provider) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	if in.TTL < 1 || in.Content == "" {
		return "", dns.ErrInvalidDNSRequest
	}
	old, index, err := p.current(ctx, zone, id)
	if err != nil {
		return "", err
	}
	// A value-scoped edit must not silently change TTL on the other answers.
	if len(old.ResourceRecords) > 1 && int64(in.TTL) != sdk.ToInt64(old.TTL) {
		return "", dns.ErrInvalidDNSRequest
	}
	content, err := dnsutil.MXValue(string(old.Type), in.Content, nil, sdk.ToString(old.ResourceRecords[index].Value))
	if err != nil {
		return "", err
	}
	value := rdata(old.Type, content)
	next := *old
	next.TTL = sdk.Int64(int64(in.TTL))
	next.ResourceRecords = slices.Clone(old.ResourceRecords)
	for i, r := range next.ResourceRecords {
		if i != index && sdk.ToString(r.Value) == value {
			return "", dns.ErrInvalidDNSRequest
		}
	}
	next.ResourceRecords[index].Value = &value
	if err := p.change(ctx, zone, old, &next); err != nil {
		return "", err
	}
	return recordID(zone, next, value), nil
}

func (p *provider) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	old, index, err := p.current(ctx, zone, id)
	if err != nil {
		return "", err
	}
	var next *types.ResourceRecordSet
	if len(old.ResourceRecords) > 1 {
		copied := *old
		copied.ResourceRecords = slices.Delete(slices.Clone(old.ResourceRecords), index, index+1)
		next = &copied
	}
	if err := p.change(ctx, zone, old, next); err != nil {
		return "", err
	}
	return id, nil
}

func (p *provider) ZoneDetails(ctx context.Context, zone string) (*dns.ZoneDetails, error) {
	if !zoneID.MatchString(zone) {
		return nil, dns.ErrInvalidDNSRequest
	}
	res, err := p.client.GetHostedZone(ctx, &route53.GetHostedZoneInput{Id: &zone})
	if err != nil || res.HostedZone == nil {
		return nil, failure
	}
	if strings.TrimPrefix(sdk.ToString(res.HostedZone.Id), "/hostedzone/") != zone {
		return nil, domain.ErrRecordNotFound
	}
	name, err := dnsutil.ZoneName(sdk.ToString(res.HostedZone.Name))
	if err != nil {
		return nil, failure
	}
	info := &dns.ZoneDetails{Name: name, Status: "active", MinTTL: 60, Lines: []dns.RecordLine{{ID: "default", Name: "Default"}}}
	if res.DelegationSet != nil {
		info.Nameservers = res.DelegationSet.NameServers
	}
	return info, nil
}

func (p *provider) CreateZone(ctx context.Context, raw string) (*dns.Zone, error) {
	name, err := dnsutil.ZoneName(raw)
	if err != nil {
		return nil, err
	}
	ref := "certimate-" + rand.Text()
	out, err := p.client.CreateHostedZone(ctx, &route53.CreateHostedZoneInput{Name: &name, CallerReference: &ref})
	if err != nil || out.HostedZone == nil {
		return nil, failure
	}
	id := strings.TrimPrefix(sdk.ToString(out.HostedZone.Id), "/hostedzone/")
	if !zoneID.MatchString(id) || !strings.EqualFold(strings.TrimSuffix(sdk.ToString(out.HostedZone.Name), "."), name) {
		return nil, failure
	}
	return &dns.Zone{ID: id, Name: name, Status: "active"}, nil
}
