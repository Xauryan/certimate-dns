package dnsautomation

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type statusWriter interface {
	SetDNSRecordStatus(context.Context, string, string, bool) (string, error)
}

// Some adapters expose status through their batch-attribute implementation.
type attributeWriter interface {
	BatchFields() []string
	SetBatchAttribute(context.Context, string, string, string, string) error
}

func canSetStatus(p dns.Provider) bool {
	if _, ok := p.(statusWriter); ok {
		return true
	}
	w, ok := p.(attributeWriter)
	return ok && slices.Contains(w.BatchFields(), "status")
}

func sameValue(kind, a, b string) bool {
	if kind == "CNAME" {
		return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
	}
	x, e := netip.ParseAddr(a)
	y, f := netip.ParseAddr(b)
	return e == nil && f == nil && x == y
}

func enabled(status string) (bool, bool) {
	switch strings.ToLower(status) {
	case "enable", "enabled", "active", "1":
		return true, true
	case "disable", "disabled", "paused", "0":
		return false, true
	}
	return false, false
}

func sameRecord(a, b *dns.DNSRecord) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ax, ak := enabled(a.Status)
	bx, bk := enabled(b.Status)
	return a.ID == b.ID && a.Description == b.Description && a.ReadOnly == b.ReadOnly && sameNumber(a.Weight, b.Weight) && sameNumber(a.Priority, b.Priority) && strings.EqualFold(strings.TrimSuffix(a.Name, "."), strings.TrimSuffix(b.Name, ".")) && a.Type == b.Type &&
		sameValue(a.Type, a.Content, b.Content) && a.TTL == b.TTL && a.Line == b.Line && a.Proxied == b.Proxied &&
		((ak && bk && ax == bx) || a.Status == b.Status)
}

func sameNumber(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

type exactReader interface {
	AutomationRecord(context.Context, string, string) (*dns.DNSRecord, error)
}
type proxyWriter interface {
	PatchDNSRecordProxy(context.Context, string, string, dns.RecordPatch, bool) (string, error)
}

func checkIdentity(r *dns.DNSRecord, t Target) (*dns.DNSRecord, error) {
	if r.ID != t.RecordID || !strings.EqualFold(strings.TrimSuffix(r.Name, "."), strings.TrimSuffix(t.Name, ".")) || r.Type != t.Type || !addressValue(t.Type, r.Content) {
		return nil, errIdentity
	}
	return r, nil
}

func lookup(ctx context.Context, p dns.Provider, t Target) (*dns.DNSRecord, error) {
	if reader, ok := p.(exactReader); ok {
		r, err := reader.AutomationRecord(ctx, t.ZoneID, t.RecordID)
		if err != nil {
			return nil, errProvider
		}
		if r == nil {
			return nil, errMissing
		}
		return checkIdentity(r, t)
	}
	for page := 1; page <= 500; page++ {
		rs, err := p.DNSRecords(ctx, t.ZoneID, page, t.Name)
		if err != nil || rs == nil {
			return nil, errProvider
		}
		for i := range rs.Items {
			r := rs.Items[i]
			if r.ID != t.RecordID {
				continue
			}
			return checkIdentity(&r, t)
		}
		if page*dns.DNSPageSize >= rs.Info.Total {
			return nil, errMissing
		}
		if len(rs.Items) == 0 {
			return nil, errProvider
		}
	}
	return nil, errProvider
}

func (s *Service) read(ctx context.Context, t Target) (dns.Provider, *dns.DNSRecord, error) {
	if s.resolve == nil {
		return nil, nil, errProvider
	}
	p, err := s.resolve(ctx, t)
	if err != nil || p == nil {
		return nil, nil, errProvider
	}
	r, err := lookup(ctx, p, t)
	return p, r, err
}

func preflight(d Definition, position string, p dns.Provider, r *dns.DNSRecord) error {
	if d.BackupProxied || d.Schedule.Proxied != nil {
		if _, ok := p.(proxyWriter); !ok {
			return errProvider
		}
		if d.BackupProxied && r.Proxied != (position == "backup") {
			return errIdentity
		}
	}
	if r.ReadOnly && d.Action != "observe" {
		return errProvider
	}
	if d.Action == "enable" || d.Action == "disable" || d.Action == "standby" {
		if !canSetStatus(p) {
			return errProvider
		}
		if _, ok := enabled(r.Status); !ok {
			return errProvider
		}
	}
	if d.Kind != "failover" {
		return nil
	}
	if d.Action == "disable" || d.Action == "standby" {
		on, _ := enabled(r.Status)
		if on != ((d.Action == "disable") == (position == "primary")) {
			return errIdentity
		}
	}
	if d.Action == "standby" {
		return nil
	}
	expected := d.Primary
	if position == "backup" && d.Action == "replace" {
		expected = d.Backup
	}
	if !sameValue(d.Target.Type, expected, r.Content) {
		return errIdentity
	}
	return nil
}

func snapshot(r *dns.DNSRecord) string {
	if r == nil {
		return "null"
	}
	b, _ := json.Marshal(r)
	return string(b)
}
func decodeSnapshot(value string) (*dns.DNSRecord, error) {
	var result *dns.DNSRecord
	err := json.Unmarshal([]byte(value), &result)
	return result, err
}

func readComparable(ctx context.Context, p dns.Provider, t Target) (*dns.DNSRecord, error) {
	r, err := lookup(ctx, p, t)
	if errors.Is(err, errMissing) {
		return nil, nil
	}
	return r, err
}

func write(ctx context.Context, p dns.Provider, t Target, action string, before, want *dns.DNSRecord) (string, error) {
	switch action {
	case "update", "replace", "restore":
		if before.Proxied != want.Proxied {
			w, ok := p.(proxyWriter)
			if !ok {
				return "", errProvider
			}
			return w.PatchDNSRecordProxy(ctx, t.ZoneID, t.RecordID, dns.RecordPatch{Content: want.Content, TTL: want.TTL}, want.Proxied)
		}
		return p.PatchDNSRecord(ctx, t.ZoneID, t.RecordID, dns.RecordPatch{Content: want.Content, TTL: want.TTL})
	case "enable", "disable":
		if w, ok := p.(statusWriter); ok {
			return w.SetDNSRecordStatus(ctx, t.ZoneID, t.RecordID, action == "enable")
		}
		if w, ok := p.(attributeWriter); ok && canSetStatus(p) {
			status := "disabled"
			if action == "enable" {
				status = "enabled"
			}
			return t.RecordID, w.SetBatchAttribute(ctx, t.ZoneID, t.RecordID, "status", status)
		}
		return "", errProvider
	case "delete":
		return p.DeleteDNSRecord(ctx, t.ZoneID, t.RecordID)
	default:
		return "", errInput
	}
}
