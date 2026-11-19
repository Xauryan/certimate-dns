package dnsbatch

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

// Deferred attributes use provider operations whose target can only be known
// after creation. Each is included in the preview and independently authorized.
func createAttributes(caps dns.Capabilities, c Change) []Change {
	var attrs []Change
	if c.Weight != nil && !caps.Weight {
		attrs = append(attrs, Change{Action: "weight", Value: strconv.Itoa(*c.Weight)})
	}
	if c.Description != "" && !caps.Description {
		attrs = append(attrs, Change{Action: "remark", Value: c.Description})
	}
	if c.Group != "" {
		attrs = append(attrs, Change{Action: "group", Value: c.Group})
	}
	if c.Status == "disabled" {
		attrs = append(attrs, Change{Action: "status", Value: c.Status})
	}
	return attrs
}
func checkCreateAttributes(ctx context.Context, p dns.Provider, provider, zone string, c Change) error {
	caps, _ := dns.ProviderCapabilities(provider)
	for _, a := range createAttributes(caps, c) {
		if !slices.Contains(fields(p), a.Action) {
			return errors.New("provider cannot preserve requested " + a.Action)
		}
	}
	if c.Group != "" {
		groupAPI, ok := p.(Groups)
		if !ok {
			return errors.New("provider does not support record groups")
		}
		items, err := groupAPI.BatchGroups(ctx, zone)
		if err != nil {
			return errors.New("could not resolve target record groups")
		}
		if !slices.ContainsFunc(items, func(g Group) bool { return g.ID == c.Group }) {
			return errors.New("record group is unavailable in this zone")
		}
	}
	return nil
}
func createInput(c Change, caps dns.Capabilities) dns.RecordInput {
	in := dns.RecordInput{Name: c.Name, Type: c.Type, Content: c.Content, TTL: c.TTL, Line: c.Line, Priority: c.Priority}
	// Some APIs return the full MX RDATA while others expose preference and target separately.
	if c.Type == "MX" {
		if f := strings.Fields(c.Content); len(f) == 2 {
			pref, err := strconv.Atoi(f[0])
			if err == nil && (c.Priority == nil || *c.Priority == pref) {
				in.Priority = &pref
				in.Content = f[1]
			}
		}
	}
	if caps.Weight {
		in.Weight = c.Weight
	}
	if caps.Description {
		in.Description = c.Description
	}
	return in
}
func expectedAttributes(c Change) map[string]string {
	out := map[string]string{}
	if c.Weight != nil {
		out["weight"] = digest(strconv.Itoa(*c.Weight))
	}
	if c.Priority != nil {
		out["priority"] = digest(strconv.Itoa(*c.Priority))
	}
	if c.Description != "" {
		out["remark"] = digest(c.Description)
	}
	if c.Status != "" {
		out["status"] = digest(c.Status)
	}
	if c.Group != "" {
		out["group"] = digest(c.Group)
	}
	return out
}
func logicalRecord(r dns.DNSRecord, provider, origin string) dns.DNSRecord {
	if provider == "cloudflare" {
		owner := canonicalName(r.Name)
		z := canonicalName(origin)
		label, ok := strings.CutSuffix(owner, "."+z)
		r.Status = "enabled"
		if ok && strings.HasSuffix(label, "_pause") {
			label = strings.TrimSuffix(label, "_pause")
			if label == "__root__" {
				r.Name = z
			} else if label != "" {
				r.Name = label + "." + z
			}
			r.Status = "disabled"
		}
		if r.Proxied {
			r.Line = "1"
		} else {
			r.Line = "0"
		}
	}
	return r
}
func projectedAttribute(ctx context.Context, p dns.Provider, zone string, r dns.DNSRecord, field string) (string, error) {
	if slices.Contains(fields(p), field) {
		return readAttribute(ctx, p, zone, r.ID, field)
	}
	switch field {
	case "remark":
		return r.Description, nil
	case "status":
		switch strings.ToLower(r.Status) {
		case "", "1", "true", "normal", "active", "enable", "enabled":
			return "enabled", nil
		case "0", "false", "paused", "inactive", "disable", "disabled":
			return "disabled", nil
		}
		return r.Status, nil
	case "weight":
		if r.Weight != nil {
			return strconv.Itoa(*r.Weight), nil
		}
	case "priority":
		if r.Priority != nil {
			return strconv.Itoa(*r.Priority), nil
		}
		if parts := strings.Fields(r.Content); r.Type == "MX" && len(parts) == 2 {
			return parts[0], nil
		}
	}
	return "", nil
}
func (item *Item) verifyCreate(ctx context.Context, p dns.Provider, s scope, origin string, rows []dns.DNSRecord) (string, error) {
	matched := ""
	for _, raw := range rows {
		if item.ID != "" && raw.ID != item.ID {
			continue
		}
		r := logicalRecord(raw, s.provider, origin)
		if desiredKey(matchingData(r, s.provider, item.MatchLine, item.MatchPriority)) != item.After {
			continue
		}
		ok := true
		for field, hash := range item.Expected {
			v, err := projectedAttribute(ctx, p, s.zone, r, field)
			if err != nil {
				return "", err
			}
			if digest(v) != hash {
				ok = false
				break
			}
		}
		if ok {
			if matched != "" {
				return "", nil
			}
			matched = r.ID
		}
	}
	return matched, nil
}

type archiveRecord struct {
	dns.DNSRecord
	Group string `json:"group,omitempty"`
}
type zoneArchive struct {
	Schema   string          `json:"schema"`
	Version  int             `json:"version"`
	Provider string          `json:"provider"`
	AccessID string          `json:"accessId"`
	ZoneID   string          `json:"zoneId"`
	Zone     string          `json:"zone"`
	Groups   []Group         `json:"groups,omitempty"`
	Records  []archiveRecord `json:"records"`
}

func archive(r request, rows []dns.DNSRecord) (zoneArchive, error) {
	out := zoneArchive{Schema: "certimate.dns.zone", Version: 1, Provider: r.s.provider, AccessID: r.s.access, ZoneID: r.s.zone, Zone: r.origin, Records: make([]archiveRecord, 0, len(rows))}
	ctx := r.e.Request.Context()
	groups, assignments, err := groupMembership(ctx, r.client, r.s.zone, rows)
	if err != nil {
		return zoneArchive{}, err
	}
	out.Groups = groups
	for _, row := range rows {
		out.Records = append(out.Records, archiveRecord{DNSRecord: logicalRecord(row, r.s.provider, r.origin), Group: assignments[row.ID]})
	}
	return out, nil
}

// Providers that inventory groups once avoid reading every group for each
// record. The caller still joins assignments to records from its scoped inventory.
func groupMembership(ctx context.Context, p dns.Provider, zone string, rows []dns.DNSRecord) ([]Group, map[string]string, error) {
	g, ok := p.(Groups)
	if !ok {
		return nil, nil, nil
	}
	groups, err := g.BatchGroups(ctx, zone)
	if err != nil {
		return nil, nil, err
	}
	if bulk, ok := p.(interface {
		BatchGroupIndex(context.Context, string, []dns.RecordGroup) (map[string]string, error)
	}); ok {
		assignments, err := bulk.BatchGroupIndex(ctx, zone, groups)
		return groups, assignments, err
	}
	assignments := make(map[string]string, len(rows))
	for _, r := range rows {
		id, err := g.BatchGroup(ctx, zone, r.ID)
		if err != nil {
			return nil, nil, err
		}
		if id != "" {
			assignments[r.ID] = id
		}
	}
	return groups, assignments, nil
}
