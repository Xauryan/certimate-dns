package dnsmanagement

import (
	"context"
	"errors"
	"hash/maphash"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"

	dns "github.com/miekg/dns"
)

var (
	ErrRecordEditConflict  = errors.New("DNS record changed or destination conflicts; refresh the record list")
	ErrRecordEditDenied    = errors.New("DNS record edit authorization is no longer active")
	ErrRecordEditUncertain = errors.New("DNS record write was submitted but its complete result could not be confirmed; inspect the provider before retrying")
	ErrRecordEditRead      = errors.New("could not obtain a complete DNS record inventory before editing")
)

// Serialize rich edits to a zone in this process, including readback. A bounded
// set of stripes avoids retaining a lock for each zone ever accessed.
var editSeed = maphash.MakeSeed()
var editSlots = func() [128]chan struct{} {
	var slots [128]chan struct{}
	for i := range slots {
		slots[i] = make(chan struct{}, 1)
	}
	return slots
}()

// ReplaceVerified submits at most one provider write. It resolves the resulting
// ID from a fresh complete inventory, including after an ambiguous transport
// error. An inconclusive result never triggers another write.
func ReplaceVerified(ctx context.Context, p Provider, zoneID, zoneName string, prior DNSRecord, desired RecordInput, authorized func() bool) (string, error) {
	editor, ok := p.(RecordEditor)
	if !ok || zoneID == "" || prior.ID == "" || !editOwnerInZone(prior.Name, zoneName) || !editOwnerInZone(desired.Name, zoneName) ||
		prior.ReadOnly || editAuthority(prior.Name, prior.Type, zoneName) || editAuthority(desired.Name, desired.Type, zoneName) ||
		desired.Type == "" || desired.Content == "" || desired.TTL < 0 {
		return "", ErrInvalidDNSRequest
	}
	if authorized == nil || !authorized() {
		return "", ErrRecordEditDenied
	}
	want := prior
	want.Name, want.Type, want.Content, want.TTL, want.Priority = desired.Name, desired.Type, desired.Content, desired.TTL, desired.Priority
	if desired.Line != prior.Line || desired.Description != prior.Description || !sameEditInt(desired.Weight, prior.Weight) {
		return "", ErrInvalidDNSRequest
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	caps, err := RecordEditCapabilitiesForZone(ctx, p, zoneID)
	if err != nil {
		return "", ErrRecordEditRead
	}
	if caps.PresentationTXT && strings.EqualFold(want.Type, "TXT") {
		want.Content = QuoteRecordTXT(want.Content)
	}
	sameType := editType(want.Type) == editType(prior.Type)
	if !caps.Rename && editName(want.Name) != editName(prior.Name) || !caps.Retype && !sameType {
		return "", ErrInvalidDNSRequest
	}
	oldValue, oldOK := editData(prior)
	newValue, newOK := editData(want)
	if !oldOK || !newOK || !caps.Priority && sameType && oldValue.priority != newValue.priority {
		return "", ErrInvalidDNSRequest
	}
	slot := editSlots[maphash.String(editSeed, zoneID)%uint64(len(editSlots))]
	select {
	case slot <- struct{}{}:
		defer func() { <-slot }()
	case <-ctx.Done():
		return "", ctx.Err()
	}

	before, err := inspectEdit(ctx, p, zoneID, zoneName, prior, want, authorized)
	if err != nil {
		return "", err
	}
	if !before.hasPrior || !sameEditState(before.prior, prior) || before.prior.UpdatedAt != prior.UpdatedAt || before.collides {
		return "", ErrRecordEditConflict
	}
	if sameEditState(before.prior, want) {
		return prior.ID, nil
	}
	if !authorized() {
		return "", ErrRecordEditDenied
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	writeCtx, stop := context.WithTimeout(ctx, 20*time.Second)
	reported, _ := editor.ReplaceDNSRecord(writeCtx, zoneID, prior, desired)
	stop()
	// Some APIs report an error even when a change took effect. Readback alone
	// determines whether to acknowledge the replacement.
	for _, wait := range []time.Duration{0, 150 * time.Millisecond, 450 * time.Millisecond} {
		if err := waitEditReadback(ctx, wait); err != nil || !authorized() {
			break
		}
		after, err := inspectEdit(ctx, p, zoneID, zoneName, prior, want, authorized)
		if errors.Is(err, ErrRecordEditDenied) {
			break
		}
		if err != nil {
			continue
		}
		if after.matches == 1 && !after.collidesWithOtherCandidate && siblingsPreserved(before, after, prior.ID, after.match.ID) && (reported == "" || reported == after.match.ID) &&
			(after.match.ID == prior.ID || !after.hasPrior && !before.ids[after.match.ID]) {
			if !authorized() {
				return "", ErrRecordEditUncertain
			}
			return after.match.ID, nil
		}
	}
	return "", ErrRecordEditUncertain
}

func waitEditReadback(ctx context.Context, delay time.Duration) error {
	if delay == 0 {
		return ctx.Err()
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type editInventory struct {
	affected                                       map[string]DNSRecord
	ids                                            map[string]bool
	prior, match                                   DNSRecord
	hasPrior, collides, collidesWithOtherCandidate bool
	matches                                        int
}

// Filters in the provider API have different search semantics. Walk a complete
// authorized zone to detect both stale IDs and IDs reused on unrelated owners.
func inspectEdit(ctx context.Context, p Provider, zoneID, zoneName string, prior, want DNSRecord, authorized func() bool) (editInventory, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	inv := editInventory{ids: map[string]bool{}, affected: map[string]DNSRecord{}}
	total := -1
	for page := 1; ; page++ {
		if !authorized() {
			return inv, ErrRecordEditDenied
		}
		if err := ctx.Err(); err != nil {
			return inv, ErrRecordEditRead
		}
		out, err := p.DNSRecords(ctx, zoneID, page, "")
		if err != nil || out == nil || out.Info.Page != page || out.Info.Total < 0 || out.Info.Total > 20000 || total >= 0 && out.Info.Total != total {
			return inv, ErrRecordEditRead
		}
		total = out.Info.Total
		count := min(DNSPageSize, total-(page-1)*DNSPageSize)
		if count < 0 || len(out.Items) != count {
			return inv, ErrRecordEditRead
		}
		for _, r := range out.Items {
			if r.ID == "" || r.Type == "" || inv.ids[r.ID] || !editOwnerInZone(r.Name, zoneName) {
				return inv, ErrRecordEditRead
			}
			inv.ids[r.ID] = true
			if editName(r.Name) == editName(prior.Name) || editName(r.Name) == editName(want.Name) {
				inv.affected[r.ID] = r
			}
			if r.ID == prior.ID {
				inv.hasPrior, inv.prior = true, r
			}
			if editName(r.Name) != editName(want.Name) || r.Line != want.Line {
				continue
			}
			matches := sameEditState(r, want)
			if matches {
				inv.matches++
				inv.match = r
			}
			collision := sameEditData(r, want) || !strings.EqualFold(r.Type, want.Type) && (strings.EqualFold(r.Type, "CNAME") || strings.EqualFold(want.Type, "CNAME"))
			if collision && r.ID != prior.ID {
				inv.collides = true
			}
			if collision && !matches {
				inv.collidesWithOtherCandidate = true
			}
		}
		if len(inv.ids) == total {
			return inv, nil
		}
	}
}

// Native updates can operate on entire record sets. A lost sibling makes the
// update inconclusive even if the replacement itself is visible.
func siblingsPreserved(before, after editInventory, oldID, newID string) bool {
	if len(before.affected) != len(after.affected) {
		return false
	}
	for id, r := range before.affected {
		if id == oldID {
			continue
		}
		current, ok := after.affected[id]
		if id == newID || !ok || !sameEditState(r, current) {
			return false
		}
	}
	return true
}

func editName(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }
func editOwnerInZone(owner, zone string) bool {
	owner, zone = editName(owner), editName(zone)
	if owner == "" || zone == "" || strings.ContainsAny(owner+zone, "\\()@;\"") || strings.IndexFunc(owner+zone, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return false
	}
	_, valid := dns.IsDomainName(owner)
	_, validZone := dns.IsDomainName(zone)
	return valid && validZone && (owner == zone || strings.HasSuffix(owner, "."+zone))
}
func editAuthority(name, kind, zone string) bool {
	return strings.EqualFold(kind, "SOA") || editName(name) == editName(zone) && strings.EqualFold(kind, "NS")
}

type editValue struct {
	content  string
	priority int // -1 denotes absent, distinct from an explicit preference of zero.
}

func editData(r DNSRecord) (editValue, bool) {
	v := editValue{content: r.Content, priority: -1}
	// Some providers populate their MX column for all types. Only MX and URI
	// expose a separate meaningful priority in the common DNS record model.
	if r.Priority != nil && (strings.EqualFold(r.Type, "MX") || strings.EqualFold(r.Type, "URI")) {
		if *r.Priority < 0 || *r.Priority > 65535 {
			return v, false
		}
		v.priority = *r.Priority
	}
	switch strings.ToUpper(r.Type) {
	case "A", "AAAA":
		ip, err := netip.ParseAddr(r.Content)
		if err != nil || ip.Zone() != "" || strings.EqualFold(r.Type, "A") != ip.Is4() {
			return v, false
		}
		v.content = ip.String()
	case "CNAME", "PTR", "NS", "DNAME", "ALIAS", "ANAME":
		v.content = editName(r.Content)
	case "MX":
		parts := strings.Fields(r.Content)
		switch len(parts) {
		case 2:
			p, err := strconv.ParseUint(parts[0], 10, 16)
			if err != nil || r.Priority != nil && int(p) != *r.Priority {
				return v, false
			}
			v.priority = int(p)
			v.content = editName(parts[1])
		case 1:
			v.content = editName(parts[0])
		default:
			return v, false
		}
	case "SRV":
		f := strings.Fields(r.Content)
		if len(f) != 4 {
			return v, false
		}
		for i := 0; i < 3; i++ {
			n, err := strconv.ParseUint(f[i], 10, 16)
			if err != nil {
				return v, false
			}
			f[i] = strconv.FormatUint(n, 10)
		}
		f[3] = editName(f[3])
		v.content = strings.Join(f, " ")
	}
	return v, true
}

func sameEditInt(a, b *int) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }

func editType(kind string) string {
	kind = strings.ToUpper(kind)
	switch kind {
	case "EXPLICIT_URL":
		return "REDIRECT_URL"
	case "IMPLICIT_URL":
		return "FORWARD_URL"
	}
	return kind
}

func sameEditData(a, b DNSRecord) bool {
	if editType(a.Type) != editType(b.Type) {
		return false
	}
	left, ok := editData(a)
	right, ok2 := editData(b)
	if ok && ok2 {
		return left == right
	}
	return !ok && !ok2 && a.Content == b.Content && sameEditInt(a.Priority, b.Priority)
}
func sameEditState(a, b DNSRecord) bool {
	return editName(a.Name) == editName(b.Name) && sameEditData(a, b) && a.TTL == b.TTL && a.Line == b.Line &&
		a.Description == b.Description && a.Proxied == b.Proxied && sameEditInt(a.Weight, b.Weight) && a.ReadOnly == b.ReadOnly && strings.EqualFold(a.Status, b.Status)
}
