// Package dnsbatch previews scoped DNS changes and records the outcome of each provider call.
package dnsbatch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"slices"
	"strings"
	"unicode"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	zonefile "github.com/miekg/dns"
)

const maxChanges = 200
const maxRecords = 20000

type Group = dns.RecordGroup
type Log = dns.RecordLog

// Metadata is optional. BatchAttribute reads the provider's canonical value.
// SetBatchAttribute changes only that attribute on the specified zone and record.
type Metadata interface {
	BatchFields() []string
	BatchAttribute(context.Context, string, string, string) (string, error)
	SetBatchAttribute(context.Context, string, string, string, string) error
}
type Groups interface {
	BatchGroups(context.Context, string) ([]Group, error)
	BatchGroup(context.Context, string, string) (string, error)
	SetBatchGroup(context.Context, string, string, string) error
}

func fields(p dns.Provider) []string {
	out := []string{}
	if m, ok := p.(Metadata); ok {
		out = append(out, m.BatchFields()...)
	}
	if _, ok := p.(Groups); ok {
		out = append(out, "group")
	}
	return out
}
func readAttribute(ctx context.Context, p dns.Provider, zone, id, field string) (string, error) {
	if field == "group" {
		if g, ok := p.(Groups); ok {
			return g.BatchGroup(ctx, zone, id)
		}
	}
	if m, ok := p.(Metadata); ok {
		return m.BatchAttribute(ctx, zone, id, field)
	}
	return "", errors.New("unsupported provider attribute")
}

type ProviderHistory interface {
	BatchLogs(context.Context, string, int) (*dns.DNSPage[Log], error)
}

type Change struct {
	Action      string `json:"action"`
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Type        string `json:"type,omitempty"`
	Content     string `json:"content,omitempty"`
	Line        string `json:"line,omitempty"`
	Priority    *int   `json:"priority,omitempty"`
	Weight      *int   `json:"weight,omitempty"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status,omitempty"`
	Group       string `json:"group,omitempty"`
	TTL         int    `json:"ttl,omitempty"`
	Value       string `json:"value,omitempty"`
}

// Item is persisted before execution. Only fingerprints of DNS payloads are retained.
type Item struct {
	Action        string            `json:"action"`
	ID            string            `json:"id,omitempty"`
	State         string            `json:"state"`
	MatchLine     bool              `json:"matchLine,omitempty"`
	MatchPriority bool              `json:"matchPriority,omitempty"`
	Expected      map[string]string `json:"expected,omitempty"`
	Before        string            `json:"before,omitempty"`
	After         string            `json:"after,omitempty"`
}
type PreviewRow struct {
	Before        *dns.DNSRecord `json:"before,omitempty"`
	Change        Change         `json:"change"`
	PreviousValue *string        `json:"previousValue,omitempty"`
}

func digest(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	} // All callers use plain serializable DNS model values.
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func Records(ctx context.Context, p dns.Provider, zone string) ([]dns.DNSRecord, error) {
	rows := []dns.DNSRecord{}
	seen := map[string]bool{}
	total := -1
	for page := 1; ; page++ {
		result, err := p.DNSRecords(ctx, zone, page, "")
		if err != nil {
			return nil, err
		}
		if result == nil || result.Info.Page != page || result.Info.Total < 0 || result.Info.Total > maxRecords || (total >= 0 && result.Info.Total != total) {
			return nil, errors.New("incomplete or changing record inventory")
		}
		total = result.Info.Total
		for _, row := range result.Items {
			if row.ID == "" || seen[row.ID] {
				return nil, errors.New("duplicate or missing provider record identifier")
			}
			seen[row.ID] = true
			rows = append(rows, row)
		}
		if len(rows) == total {
			return rows, nil
		}
		if len(rows) > total || len(result.Items) == 0 {
			return nil, errors.New("incomplete provider inventory")
		}
	}
}

// Require the complete inventory to belong to the selected zone before exposing or using any rows.
func zoneRecords(ctx context.Context, p dns.Provider, zone, origin string) ([]dns.DNSRecord, error) {
	rows, err := Records(ctx, p, zone)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if !withinZone(row.Name, origin) {
			return nil, errors.New("provider returned a record outside the selected zone")
		}
	}
	return rows, nil
}
func withinZone(name, origin string) bool {
	return validName(name) && validName(origin) && zonefile.IsSubDomain(zonefile.Fqdn(origin), zonefile.Fqdn(name))
}
func canonicalName(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }
func validName(s string) bool {
	if s == "" || strings.ContainsAny(s, "\\;()@\"") || strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return false
	}
	_, ok := zonefile.IsDomainName(s)
	return ok
}
func ValidChange(c Change, origin, provider string) error {
	if !withinZone(c.Name, origin) {
		return errors.New("record owner is outside the zone or malformed")
	}
	caps, ok := dns.ProviderCapabilities(provider)
	if !ok || !caps.AllowsType(c.Type) {
		return errors.New("record type unavailable for provider")
	}
	if !caps.AllowsTTL(c.TTL) {
		return errors.New("invalid TTL for provider")
	}
	if c.Line != "" && (!caps.Line || len(c.Line) > 255 || strings.TrimSpace(c.Line) != c.Line || strings.IndexFunc(c.Line, unicode.IsControl) >= 0) {
		return errors.New("invalid or unsupported record line")
	}
	if c.Priority != nil && (!slices.Contains(caps.PriorityTypes, c.Type) || *c.Priority < 0 || *c.Priority > 65535) {
		return errors.New("invalid or unsupported record priority")
	}
	if c.Weight != nil && (*c.Weight < 0 || *c.Weight > 65535) {
		return errors.New("invalid record weight")
	}
	if len(c.Description) > 512 || strings.IndexFunc(c.Description, unicode.IsControl) >= 0 {
		return errors.New("invalid record remark")
	}
	if c.Status != "" && c.Status != "enabled" && c.Status != "disabled" {
		return errors.New("invalid record status")
	}
	if len(c.Group) > 255 || strings.IndexFunc(c.Group, unicode.IsControl) >= 0 {
		return errors.New("invalid record group")
	}
	return validateData(c)
}
func contentKey(c Change) string {
	return digest([]string{canonicalName(c.Name), c.Type, canonicalContent(c), c.Line})
}
func matchPriority(c Change) bool {
	return c.Type == "MX" && (c.Priority != nil || len(strings.Fields(c.Content)) == 2)
}
func dataOf(r dns.DNSRecord) Change {
	return Change{Name: r.Name, Type: r.Type, TTL: r.TTL, Content: r.Content}
}
func matchingData(r dns.DNSRecord, provider string, withLine, withPriority bool) Change {
	c := dataOf(r)
	if c.Type == "MX" {
		if withPriority {
			c.Priority = r.Priority
		} else if f := strings.Fields(c.Content); len(f) == 2 {
			c.Content = f[1]
		}
	}
	if withLine {
		c.Line = r.Line
		if provider == "cloudflare" {
			c.Line = "0"
			if r.Proxied {
				c.Line = "1"
			}
		}
	}
	return c
}
func byID(rows []dns.DNSRecord, id string) *dns.DNSRecord {
	for i := range rows {
		if rows[i].ID == id {
			return &rows[i]
		}
	}
	return nil
}
func desiredKey(c Change) string { return digest([]any{contentKey(c), c.TTL}) }

func prepare(ctx context.Context, p dns.Provider, provider, zone, origin string, rows []dns.DNSRecord, changes []Change) ([]Item, []PreviewRow, error) {
	if len(changes) == 0 || len(changes) > maxChanges {
		return nil, nil, errors.New("batch requires 1 to 200 changes")
	}
	items := make([]Item, 0, len(changes))
	preview := make([]PreviewRow, 0, len(changes))
	targets := map[string]bool{}
	for i, c := range changes {
		item := Item{Action: c.Action, ID: c.ID, State: "ready"}
		row := PreviewRow{Change: c}
		key := c.ID
		if c.Action != "create" && (c.Line != "" || c.Priority != nil || c.Weight != nil || c.Description != "" || c.Status != "" || c.Group != "") {
			return nil, nil, fmt.Errorf("item %d: unexpected create attributes", i+1)
		}
		if c.Action == "create" {
			if c.ID != "" || c.Value != "" {
				return nil, nil, errors.New("invalid create fields")
			}
			if err := ValidChange(c, origin, provider); err != nil {
				return nil, nil, fmt.Errorf("item %d: %w", i+1, err)
			}
			if err := checkCreateAttributes(ctx, p, provider, zone, c); err != nil {
				return nil, nil, fmt.Errorf("item %d: %w", i+1, err)
			}
			item.Expected = expectedAttributes(c)
			key = "create:" + contentKey(c)
			item.MatchLine = c.Line != ""
			item.MatchPriority = matchPriority(c)
			item.Before = contentKey(c)
			item.After = desiredKey(c)
			for _, r := range rows {
				if contentKey(matchingData(logicalRecord(r, provider, origin), provider, item.MatchLine, item.MatchPriority)) == item.Before {
					return nil, nil, fmt.Errorf("item %d: record already exists", i+1)
				}
			}
		} else {
			if c.ID == "" || len(c.ID) > 512 {
				return nil, nil, errors.New("record ID required")
			}
			old := byID(rows, c.ID)
			if old == nil {
				return nil, nil, fmt.Errorf("item %d: record not found in zone", i+1)
			}
			if old.ReadOnly || !withinZone(old.Name, origin) || (canonicalName(old.Name) == canonicalName(origin) && (old.Type == "NS" || old.Type == "SOA")) {
				return nil, nil, fmt.Errorf("item %d: record is protected or outside the selected zone", i+1)
			}
			row.Before = old
			item.Before = digest(old)
			if c.Name != "" || c.Type != "" || c.Line != "" {
				return nil, nil, errors.New("record owner and type are immutable")
			}
			if c.Action != "patch" && (c.TTL != 0 || c.Content != "") {
				return nil, nil, errors.New("unexpected record data")
			}
			switch c.Action {
			case "delete":
				if c.Value != "" {
					return nil, nil, errors.New("unexpected delete value")
				}
			case "patch":
				if c.Value != "" {
					return nil, nil, errors.New("unexpected patch attribute")
				}
				in := c
				in.Name = old.Name
				in.Type = old.Type
				if caps, _ := dns.ProviderCapabilities(provider); slices.Contains(caps.PriorityTypes, old.Type) {
					in.Priority = old.Priority
				}
				if err := ValidChange(in, origin, provider); err != nil {
					return nil, nil, fmt.Errorf("item %d: %w", i+1, err)
				}
				item.MatchPriority = matchPriority(in)
				item.After = desiredKey(in)
			default:
				if !slices.Contains(fields(p), c.Action) {
					return nil, nil, errors.New("provider does not support this batch action")
				}
				if len(c.Value) > 512 || (c.Action != "remark" && c.Value == "") || (c.Action == "status" && c.Value != "enabled" && c.Value != "disabled") {
					return nil, nil, errors.New("invalid attribute value")
				}
				oldValue, err := readAttribute(ctx, p, zone, c.ID, c.Action)
				if err != nil {
					return nil, nil, fmt.Errorf("item %d: could not read provider attribute", i+1)
				}
				item.Before = digest([]any{old, oldValue})
				row.PreviousValue = &oldValue
				item.After = digest(c.Value)
			}
		}
		if targets[key] {
			return nil, nil, errors.New("duplicate batch target")
		}
		targets[key] = true
		items = append(items, item)
		preview = append(preview, row)
	}
	return items, preview, nil
}
