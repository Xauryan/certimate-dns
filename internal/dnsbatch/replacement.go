package dnsbatch

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

// Keep only fingerprints needed to reconcile a replacement after an interrupted
// write. A new record ID is attributable only if the rest of the inventory and
// the records at both owners still match the snapshot before dispatch.
type replacementScope struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Roster string `json:"roster"`
}

func prepareReplacement(ctx context.Context, p dns.Provider, provider, zone, origin string, rows []dns.DNSRecord, old dns.DNSRecord, c Change, edit dns.RecordEditCapabilities, item *Item) (dns.RecordInput, error) {
	var out dns.RecordInput
	if edit == (dns.RecordEditCapabilities{}) {
		return out, errors.New("provider does not support record replacement")
	}
	if c.Value != "" || c.Name == "" && c.Type == "" && c.Content == "" && c.TTL == 0 && c.Priority == nil {
		return out, errors.New("record replacement requires changed fields")
	}
	if old.Type == "SOA" {
		return out, errors.New("record is protected")
	}
	want := Change{Name: old.Name, Type: old.Type, Content: old.Content, TTL: old.TTL}
	if c.Name != "" {
		want.Name = c.Name
	}
	if c.Type != "" {
		want.Type = c.Type
	}
	if c.Content != "" {
		want.Content = c.Content
	}
	if c.TTL != 0 {
		want.TTL = c.TTL
	}
	if !edit.Rename && canonicalName(want.Name) != canonicalName(old.Name) || !edit.Retype && want.Type != old.Type {
		return out, errors.New("provider does not support the requested name or type change")
	}
	if canonicalName(want.Name) == canonicalName(origin) && want.Type == "NS" {
		return out, errors.New("replacement would modify zone authority")
	}
	caps, _ := dns.ProviderCapabilities(provider)
	if slices.Contains(caps.PriorityTypes, want.Type) && want.Type == old.Type {
		want.Priority = old.Priority
	}
	if want.Type == "MX" {
		fallback := 1
		if old.Type == want.Type {
			exchange, prior, err := dnsutil.MXParts(old.Content, old.Priority, fallback, 65535)
			if err != nil {
				return out, err
			}
			fallback = prior
			if c.Content == "" {
				// Preserve the exchange when the provider embeds the old
				// preference in the displayed record value.
				want.Content = exchange
			}
		}
		exchange, preference, err := dnsutil.MXParts(want.Content, c.Priority, fallback, 65535)
		if err != nil {
			return out, err
		}
		if !edit.Priority && (c.Priority != nil || preference != fallback) {
			return out, errors.New("provider does not support the requested priority change")
		}
		want.Content, want.Priority = exchange, &preference
	} else if c.Priority != nil {
		if !edit.Priority {
			return out, errors.New("provider does not support the requested priority change")
		}
		want.Priority = c.Priority
	}
	if err := ValidChange(want, origin, provider); err != nil {
		return out, err
	}
	out = dns.RecordInput{Name: want.Name, Type: want.Type, Content: want.Content, TTL: want.TTL, Priority: want.Priority, Line: old.Line, Description: old.Description, Weight: old.Weight}
	after := replacementRecord(old, out)
	for _, row := range rows {
		if row.ID != old.ID && canonicalName(row.Name) == canonicalName(after.Name) && replacementConflict(row, after) {
			return out, errors.New("record replacement conflicts with an existing record")
		}
	}
	if g, ok := p.(Groups); ok {
		group, err := g.BatchGroup(ctx, zone, old.ID)
		if err != nil {
			return out, errors.New("could not read the existing record group")
		}
		item.Expected = map[string]string{"group": digest(group)}
		item.Before = digest([]any{old, item.Expected["group"]})
	}
	item.After = replacementFingerprint(after)
	return out, nil
}

func replacementRecord(old dns.DNSRecord, want dns.RecordInput) dns.DNSRecord {
	old.Name, old.Type, old.Content, old.TTL, old.Priority = want.Name, want.Type, want.Content, want.TTL, want.Priority
	return old
}

func replacementData(row dns.DNSRecord) string {
	c := Change{Type: row.Type, Content: row.Content, Priority: row.Priority}
	if c.Type == "URI" {
		return digest([]any{canonicalContent(c), c.Priority})
	}
	return canonicalContent(c)
}

func replacementConflict(a, b dns.DNSRecord) bool {
	if a.Line != b.Line {
		return false
	}
	return a.Type == "CNAME" || b.Type == "CNAME" || a.Type == b.Type && replacementData(a) == replacementData(b)
}

func replacementFingerprint(row dns.DNSRecord) string {
	return digest([]any{canonicalName(row.Name), row.Type, replacementData(row), row.TTL, row.Line, strings.ToLower(row.Status), row.ReadOnly, row.Description, row.Weight, row.Proxied})
}

func replacementRoster(rows []dns.DNSRecord, skip, source, target string) string {
	others := make(map[string]string, len(rows))
	for _, row := range rows {
		if row.ID == skip {
			continue
		}
		owner := digest(canonicalName(row.Name))
		if owner == source || owner == target {
			others[row.ID] = replacementFingerprint(row)
		} else {
			others[row.ID] = ""
		}
	}
	return digest(others)
}

func (item *Item) replacementGroupMatches(ctx context.Context, p dns.Provider, zone, id string) (bool, error) {
	if expected, ok := item.Expected["group"]; ok {
		g, ok := p.(Groups)
		if !ok {
			return false, nil
		}
		group, err := g.BatchGroup(ctx, zone, id)
		return err == nil && digest(group) == expected, err
	}
	return true, nil
}

func (item *Item) findReplacement(ctx context.Context, p dns.Provider, zone string, rows []dns.DNSRecord) (string, error) {
	if item.Replacement == nil {
		return "", nil
	}
	var matched string
	for _, row := range rows {
		if digest(canonicalName(row.Name)) == item.Replacement.Target && replacementFingerprint(row) == item.After {
			if matched != "" {
				return "", nil
			}
			matched = row.ID
		}
	}
	base := item.Replacement
	if matched == "" || matched != item.ID && byID(rows, item.ID) != nil || replacementRoster(rows, matched, base.Source, base.Target) != base.Roster {
		return "", nil
	}
	if ok, err := item.replacementGroupMatches(ctx, p, zone, matched); !ok {
		return "", err
	}
	return matched, nil
}
