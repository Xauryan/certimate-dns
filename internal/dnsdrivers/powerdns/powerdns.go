// Package powerdns manages records using PowerDNS Authoritative's zone API.
package powerdns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	u "github.com/certimate-go/certimate/internal/dnsdrivers/selfhostutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

const zonesPath = "/api/v1/servers/localhost/zones"

var zoneID = regexp.MustCompile(`^[a-zA-Z0-9_=-]+(?:\.[a-zA-Z0-9_=-]+)*\.?$`)

type provider struct {
	client *u.Client
	header http.Header
}

func New(a *domain.Access) (dns.Provider, error) {
	key := u.Field(a, "apiKey")
	if key == "" {
		return nil, domain.ErrInvalidParams
	}
	c, err := u.NewClientWithHTTP(u.Field(a, "serverUrl"), dnsutil.HTTPClientFor(a))
	if err != nil {
		return nil, err
	}
	c.ApplyTLSConfig(a)
	return &provider{c, http.Header{"X-Api-Key": {key}}}, nil
}

type record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}
type rrset struct {
	Name     string    `json:"name"`
	Type     string    `json:"type"`
	TTL      int       `json:"ttl"`
	Records  []record  `json:"records"`
	Comments []comment `json:"comments,omitempty"`
	Change   string    `json:"changetype,omitempty"`
}

// A record-set replacement needs every member and the original TTL. A
// partially populated response must never be treated as an empty set.
func (s *rrset) UnmarshalJSON(raw []byte) error {
	type fields rrset
	var wire struct {
		*fields
		TTL *int `json:"ttl"`
	}
	wire.fields = (*fields)(s)
	if json.Unmarshal(raw, &wire) != nil || wire.TTL == nil || *wire.TTL < 0 || s.Records == nil {
		return u.ErrProvider
	}
	s.TTL = *wire.TTL
	return nil
}

type comment struct {
	Content    string `json:"content"`
	Account    string `json:"account"`
	ModifiedAt int64  `json:"modified_at,omitempty"`
}

func (r *record) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Content  *string
		Disabled *bool
	}
	if json.Unmarshal(raw, &wire) != nil || wire.Content == nil || wire.Disabled == nil {
		return u.ErrProvider
	}
	r.Content, r.Disabled = *wire.Content, *wire.Disabled
	return nil
}

type zone struct {
	ID, Name string
	RRSets   []rrset
}

func (p *provider) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	if !u.PageOK(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	var rows []zone
	if err := p.client.Call(ctx, "GET", zonesPath, nil, nil, p.header, &rows); err != nil {
		return nil, err
	}
	if rows == nil {
		return nil, u.ErrProvider
	}
	zones := make([]dns.Zone, 0, len(rows))
	for _, r := range rows {
		if !zoneID.MatchString(r.ID) || u.Name(r.Name) == "" {
			return nil, u.ErrProvider
		}
		zones = append(zones, dns.Zone{ID: r.ID, Name: u.Name(r.Name), Status: "active"})
	}
	return u.SlicePage(zones, page)
}
func (p *provider) zone(ctx context.Context, id string) (zone, error) {
	if !zoneID.MatchString(id) && id != "=2E" {
		return zone{}, dns.ErrInvalidDNSRequest
	}
	var z zone
	if err := p.client.Call(ctx, "GET", zonesPath+"/"+id, nil, nil, p.header, &z); err != nil {
		return z, err
	}
	if z.ID != id || z.Name == "" || z.RRSets == nil {
		return z, u.ErrProvider
	}
	for _, set := range z.RRSets {
		if _, err := u.Relative(set.Name, z.Name); err != nil || set.Type == "" || set.Records == nil {
			return z, u.ErrProvider
		}
	}
	return z, nil
}
func display(typ, raw string) string {
	switch typ {
	case "TXT":
		if str, ok := plainTXT(raw); ok {
			return str
		}
	case "CNAME", "NS", "PTR", "DNAME", "ALIAS":
		return u.Name(raw)
	}
	return raw
}

// PowerDNS returns DNS presentation-format strings. Numeric escapes are decimal
// octets, and TXT RDATA may consist of several consecutive quoted strings.
func plainTXT(raw string) (string, bool) {
	var text strings.Builder
	for raw != "" {
		raw = strings.TrimLeft(raw, " \t")
		if raw == "" || raw[0] != '"' {
			return "", false
		}
		i := 1
		for ; i < len(raw) && raw[i] != '"'; i++ {
			c := raw[i]
			if c == '\\' {
				i++
				if i >= len(raw) {
					return "", false
				}
				c = raw[i]
				if c >= '0' && c <= '9' {
					if i+3 > len(raw) {
						return "", false
					}
					n, err := strconv.ParseUint(raw[i:i+3], 10, 8)
					if err != nil {
						return "", false
					}
					c = byte(n)
					i += 2
				}
			}
			text.WriteByte(c)
		}
		if i == len(raw) {
			return "", false
		}
		raw = strings.TrimSpace(raw[i+1:])
	}
	return text.String(), true
}

// Encode a plain TXT string as DNS character strings of at most 255 octets.
func quoteTXT(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if i%255 == 0 {
			if i > 0 {
				out.WriteByte(' ')
			}
			out.WriteByte('"')
		}
		b := value[i]
		switch {
		case b == '"' || b == '\\':
			out.WriteByte('\\')
			out.WriteByte(b)
		case b < 32 || b > 126:
			fmt.Fprintf(&out, "\\%03d", b)
		default:
			out.WriteByte(b)
		}
		if i%255 == 254 || i+1 == len(value) {
			out.WriteByte('"')
		}
	}
	if value == "" {
		return `""`
	}
	return out.String()
}
func content(typ, value string) (string, error) {
	switch typ {
	case "A", "AAAA":
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.Zone() != "" || (typ == "A") != ip.Is4() {
			return "", dns.ErrInvalidDNSRequest
		}
		return ip.String(), nil
	case "TXT":
		return quoteTXT(value), nil
	case "CNAME", "NS", "DNAME", "PTR", "ALIAS":
		return u.Name(value) + ".", nil
	default:
		return value, nil
	}
}
func (s rrset) row(zoneID string, r record) dns.DNSRecord {
	status := "enabled"
	if r.Disabled {
		status = "disabled"
	}
	desc := ""
	if len(s.Comments) > 0 {
		desc = s.Comments[0].Content
	}
	var priority *int
	if s.Type == "MX" {
		fields := strings.Fields(r.Content)
		if len(fields) == 2 {
			if n, err := strconv.Atoi(fields[0]); err == nil {
				priority = &n
			}
		}
	}
	return dns.DNSRecord{Priority: priority, Description: desc, Line: "default", ID: u.ID(zoneID, s.Name, s.Type, r.Content), Name: u.Name(s.Name), Type: s.Type, Content: display(s.Type, r.Content), TTL: s.TTL, Status: status}
}
func (p *provider) DNSRecords(ctx context.Context, id string, page int, filter string) (*dns.DNSPage[dns.DNSRecord], error) {
	if !u.PageOK(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	z, err := p.zone(ctx, id)
	if err != nil {
		return nil, err
	}
	rows := []dns.DNSRecord{}
	for _, s := range z.RRSets {
		if !strings.Contains(u.Name(s.Name), u.Name(filter)) {
			continue
		}
		for _, r := range s.Records {
			rows = append(rows, s.row(id, r))
		}
	}
	return u.SlicePage(rows, page)
}
func (p *provider) write(ctx context.Context, z zone, changes ...rrset) error {
	return p.client.Call(ctx, "PATCH", zonesPath+"/"+z.ID, nil, struct {
		Sets []rrset `json:"rrsets"`
	}{changes}, p.header, nil)
}
func (p *provider) CreateDNSRecord(ctx context.Context, id string, in dns.RecordInput) (string, error) {
	defer u.LockZone(p.client.Base, id)()
	z, err := p.zone(ctx, id)
	if err != nil {
		return "", err
	}
	host, err := u.Relative(in.Name, z.Name)
	if err != nil {
		return "", err
	}
	if in.TTL < 1 || in.Weight != nil || in.Line != "" && in.Line != "default" {
		return "", dns.ErrInvalidDNSRequest
	}
	if in.Type == "MX" {
		in.Content, err = mxValue(in.Content, in.Priority)
		if err != nil {
			return "", err
		}
	}
	value, err := content(in.Type, in.Content)
	if err != nil {
		return "", err
	}
	s := rrset{Name: u.Full(host, z.Name) + ".", Type: in.Type, TTL: in.TTL}
	for _, old := range z.RRSets {
		if strings.EqualFold(old.Name, s.Name) && old.Type == s.Type {
			if old.TTL != in.TTL && len(old.Records) > 0 {
				return "", dns.ErrInvalidDNSRequest
			}
			if in.Description != "" && (len(old.Comments) == 0 || old.Comments[0].Content != in.Description) {
				return "", dns.ErrInvalidDNSRequest
			}
			s.Records = old.Records
			for _, r := range old.Records {
				if r.Content == value {
					return "", dns.ErrInvalidDNSRequest
				}
			}
		}
	}
	if len(s.Records) == 0 && in.Description != "" {
		s.Comments = []comment{{Content: in.Description}}
	}
	r := record{Content: value}
	s.Records = append(s.Records, r)
	s.Change = "REPLACE"
	if err = p.write(ctx, z, s); err != nil {
		return "", err
	}
	return s.row(id, r).ID, nil
}
func (z zone) find(id string) (rrset, record, error) {
	for _, s := range z.RRSets {
		for _, r := range s.Records {
			if s.row(z.ID, r).ID == id {
				return s, r, nil
			}
		}
	}
	return rrset{}, record{}, domain.ErrRecordNotFound
}
func (p *provider) PatchDNSRecord(ctx context.Context, zoneID, id string, in dns.RecordPatch) (string, error) {
	defer u.LockZone(p.client.Base, zoneID)()
	z, err := p.zone(ctx, zoneID)
	if err != nil {
		return "", err
	}
	s, old, err := z.find(id)
	if err != nil {
		return "", err
	}
	if in.TTL < 1 {
		return "", dns.ErrInvalidDNSRequest
	}
	r := old
	if s.Type == "MX" {
		priority := s.row(zoneID, old).Priority
		in.Content, err = mxValue(in.Content, priority)
		if err != nil {
			return "", err
		}
	}
	if in.Content != display(s.Type, old.Content) {
		r.Content, err = content(s.Type, in.Content)
		if err != nil {
			return "", err
		}
	}
	if len(s.Records) > 1 && s.TTL != in.TTL {
		return "", dns.ErrInvalidDNSRequest
	}
	if r.Content == old.Content && in.TTL == s.TTL {
		return id, nil
	}
	for _, other := range s.Records {
		if other.Content != old.Content && other.Content == r.Content {
			return "", dns.ErrInvalidDNSRequest
		}
	}
	for i, member := range s.Records {
		if member == old {
			s.Records[i] = r
			break
		}
	}
	s.TTL = in.TTL
	if err = p.replace(ctx, z, s); err != nil {
		return "", err
	}
	return s.row(zoneID, r).ID, nil
}
func (p *provider) DeleteDNSRecord(ctx context.Context, zoneID, id string) (string, error) {
	defer u.LockZone(p.client.Base, zoneID)()
	z, err := p.zone(ctx, zoneID)
	if err != nil {
		return "", err
	}
	s, r, err := z.find(id)
	if err != nil {
		return "", err
	}
	s.Records = slices.DeleteFunc(s.Records, func(v record) bool { return v == r })
	if err = p.replace(ctx, z, s); err != nil {
		return "", err
	}
	return id, nil
}
func (p *provider) SetDNSRecordStatus(ctx context.Context, zoneID, id string, enabled bool) (string, error) {
	defer u.LockZone(p.client.Base, zoneID)()
	z, err := p.zone(ctx, zoneID)
	if err != nil {
		return "", err
	}
	s, r, err := z.find(id)
	if err != nil {
		return "", err
	}
	for i, member := range s.Records {
		if member == r {
			s.Records[i].Disabled = !enabled
			break
		}
	}
	if err = p.replace(ctx, z, s); err != nil {
		return "", err
	}
	return id, nil
}

func (p *provider) replace(ctx context.Context, z zone, s rrset) error {
	s.Change = "REPLACE"
	s.Comments = nil // Omission preserves existing RRset comments when changing records.
	return p.write(ctx, z, s)
}
func (p *provider) CreateZone(ctx context.Context, name string) (*dns.Zone, error) {
	name, err := dnsutil.ZoneName(name)
	if err != nil {
		return nil, err
	}
	var z zone
	if err = p.client.Call(ctx, http.MethodPost, zonesPath, nil, map[string]string{"name": name + ".", "kind": "Native", "soa_edit_api": "INCREASE"}, p.header, &z); err != nil {
		return nil, err
	}
	if !zoneID.MatchString(z.ID) || u.Name(z.Name) != name {
		return nil, u.ErrProvider
	}
	return &dns.Zone{ID: z.ID, Name: name, Status: "active"}, nil
}
func (p *provider) ZoneDetails(ctx context.Context, id string) (*dns.ZoneDetails, error) {
	z, err := p.zone(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &dns.ZoneDetails{Name: u.Name(z.Name), Status: "active", MinTTL: 1, Lines: []dns.RecordLine{{ID: "default", Name: "default"}}}
	for _, s := range z.RRSets {
		if strings.EqualFold(s.Name, z.Name) && s.Type == "NS" {
			for _, r := range s.Records {
				if !r.Disabled {
					out.Nameservers = append(out.Nameservers, u.Name(r.Content))
				}
			}
		}
	}
	return out, nil
}
func (p *provider) BatchFields() []string { return []string{"status", "remark"} }
func (p *provider) BatchAttribute(ctx context.Context, zoneID, id, field string) (string, error) {
	z, err := p.zone(ctx, zoneID)
	if err != nil {
		return "", err
	}
	s, r, err := z.find(id)
	if err != nil {
		return "", err
	}
	row := s.row(zoneID, r)
	switch field {
	case "status":
		return row.Status, nil
	case "remark":
		return row.Description, nil
	}
	return "", dns.ErrInvalidDNSRequest
}
func (p *provider) SetBatchAttribute(ctx context.Context, zoneID, id, field, value string) error {
	if field == "status" && (value == "enabled" || value == "disabled") {
		_, err := p.SetDNSRecordStatus(ctx, zoneID, id, value == "enabled")
		return err
	}
	if field != "remark" {
		return dns.ErrInvalidDNSRequest
	}
	defer u.LockZone(p.client.Base, zoneID)()
	z, err := p.zone(ctx, zoneID)
	if err != nil {
		return err
	}
	s, _, err := z.find(id)
	if err != nil {
		return err
	}
	// Comments are shared by every member of the set. A per-record edit cannot change another member.
	if len(s.Records) != 1 {
		return dns.ErrInvalidDNSRequest
	}
	if len(s.Comments) == 0 {
		s.Comments = []comment{{Content: value}}
	} else if value == "" {
		s.Comments = s.Comments[1:]
	} else {
		s.Comments[0].Content = value
		s.Comments[0].ModifiedAt = 0
	}
	return p.client.Call(ctx, "PATCH", zonesPath+"/"+z.ID, nil, map[string]any{"rrsets": []any{map[string]any{"name": s.Name, "type": s.Type, "changetype": "REPLACE", "comments": s.Comments}}}, p.header, nil)
}

func mxValue(value string, priority *int) (string, error) {
	fields := strings.Fields(value)
	n := 1
	switch len(fields) {
	case 1:
		if priority != nil {
			n = *priority
		}
	case 2:
		parsed, err := strconv.ParseUint(fields[0], 10, 16)
		if err != nil {
			return "", dns.ErrInvalidDNSRequest
		}
		n = int(parsed)
	default:
		return "", dns.ErrInvalidDNSRequest
	}
	if n < 0 || n > 65535 {
		return "", dns.ErrInvalidDNSRequest
	}
	target := fields[len(fields)-1]
	if target != "." {
		name, err := dnsutil.ZoneName(target)
		if err != nil {
			return "", err
		}
		target = name + "."
	}
	return strconv.Itoa(n) + " " + target, nil
}
