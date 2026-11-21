package ddnsfleet

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnscatalog"
	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

var (
	errRecordMissing = errors.New("DNS record not found")
	errRecordRead    = errors.New("DNS record lookup failed")
	globalIPv6       = netip.MustParsePrefix("2000::/3")
)

const (
	reconcileInterval = 15 * time.Minute
	maxFailedAttempts = 6
)

func retryDelay(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	return min(15*time.Second*(1<<(min(failures, maxFailedAttempts)-1)), 5*time.Minute)
}

// Use the same wire interpretation as ReplaceVerified. Automation's detail
// reader may normalize owners or require separate zone-read privileges.
func lookupRecord(ctx context.Context, p dns.Provider, zone, id string) (*dns.DNSRecord, error) {
	total := -1
	for page := 1; page <= 1000; page++ {
		result, err := p.DNSRecords(ctx, zone, page, "")
		if err != nil || result == nil || result.Info.Page != page || result.Info.Total < 0 ||
			total >= 0 && total != result.Info.Total {
			return nil, errRecordRead
		}
		total = result.Info.Total
		count := min(dns.DNSPageSize, total-(page-1)*dns.DNSPageSize)
		if count < 0 || len(result.Items) != count {
			return nil, errRecordRead
		}
		for _, record := range result.Items {
			if record.ID == id {
				return &record, nil
			}
		}
		if page*dns.DNSPageSize >= total {
			return nil, errRecordMissing
		}
	}
	return nil, errRecordRead
}

func findInterface(interfaces []Interface, name string) *Interface {
	for i := range interfaces {
		if interfaces[i].Name == name {
			return &interfaces[i]
		}
	}
	return nil
}

func bindableRecord(record *dns.DNSRecord, zoneName string) bool {
	if record == nil || record.ID == "" || record.ReadOnly || record.TTL < 0 {
		return false
	}
	if _, err := dnsutil.RelativeName(record.Name, zoneName); err != nil {
		return false
	}
	addr, err := netip.ParseAddr(record.Content)
	return err == nil && addr.Zone() == "" && !addr.Is4In6() &&
		(strings.EqualFold(record.Type, "A") && addr.Is4() || strings.EqualFold(record.Type, "AAAA") && addr.Is6())
}

func sameOwner(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

func selectAddress(iface *Interface, kind string, preferred ...string) netip.Addr {
	if iface == nil {
		return netip.Addr{}
	}
	values := iface.IPv4
	if kind == "AAAA" {
		values = iface.IPv6
	}

	var choices []netip.Addr
	for _, value := range values {
		addr, err := netip.ParseAddr(value)
		if err == nil && addr.Zone() == "" && addr.IsGlobalUnicast() &&
			(kind == "A" && addr.Is4() || kind == "AAAA" && globalIPv6.Contains(addr)) {
			choices = append(choices, addr)
		}
	}
	for _, value := range preferred {
		addr, err := netip.ParseAddr(value)
		if err == nil && slices.Contains(choices, addr) {
			return addr
		}
	}
	if len(choices) == 0 {
		return netip.Addr{}
	}
	// Prefer a recognizable MAC-derived IPv6 address when selecting afresh.
	// Other IPv6 interface IDs are opaque, so consistently order them by value.
	slices.SortFunc(choices, func(a, b netip.Addr) int {
		switch {
		case macDerivedIPv6(a) && !macDerivedIPv6(b):
			return -1
		case !macDerivedIPv6(a) && macDerivedIPv6(b):
			return 1
		default:
			return a.Compare(b)
		}
	})
	return choices[0]
}

func macDerivedIPv6(addr netip.Addr) bool {
	value := addr.As16()
	return addr.Is6() && value[11] == 0xff && value[12] == 0xfe
}

// The worker and administrator binding/node actions share the mutations lock.
// Reports can arrive during provider calls, so only the write checks that its
// address selection still belongs to the current interface snapshot. Readback
// must still finish if a newer report arrives after the write was submitted.
type snapshotWriter struct {
	dns.Provider
	dns.RecordEditor
	canSubmit func() bool
}

func (p snapshotWriter) ZoneRecordEditCapabilities(ctx context.Context, zone string) (dns.RecordEditCapabilities, error) {
	return dns.RecordEditCapabilitiesForZone(ctx, p.Provider, zone)
}

func (p snapshotWriter) ReplaceDNSRecord(ctx context.Context, zone string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	if ctx.Err() != nil || !p.canSubmit() {
		return "", dns.ErrRecordEditDenied
	}
	return p.RecordEditor.ReplaceDNSRecord(ctx, zone, prior, desired)
}

func (s *Service) snapshotCurrent(ctx context.Context, app core.App, nodeID, snapshot string) bool {
	var found string
	err := app.DB().Select("id").From("ddns_nodes").
		Where(dbx.HashExp{"id": nodeID, "enabled": true, "report_required": false, "interfaces": snapshot}).
		AndWhere(dbx.NewExp("seen_at >= {:since}", dbx.Params{"since": s.now().Add(-onlineWindow).Unix()})).
		WithContext(ctx).Row(&found)
	return err == nil
}

func (s *Service) syncNode(ctx context.Context, app core.App, nodeID string, interfaces []Interface) {
	var bindings []struct {
		ID string `db:"id"`
	}
	err := app.DB().Select("id").From("ddns_bindings").Where(dbx.HashExp{"node_id": nodeID}).
		OrderBy("updated_at", "id").WithContext(ctx).All(&bindings)
	if err != nil {
		if ctx.Err() == nil {
			app.Logger().Error("Could not read DDNS bindings for synchronization.")
		}
		return
	}
	snapshot, err := json.Marshal(interfaces)
	if err != nil {
		return
	}
	current := func() bool {
		checkCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		return s.snapshotCurrent(checkCtx, app, nodeID, string(snapshot))
	}
	for _, binding := range bindings {
		if ctx.Err() != nil || !s.syncCurrentBinding(ctx, app, binding.ID, interfaces, current) {
			return
		}
	}
}

func (s *Service) syncCurrentBinding(parent context.Context, app core.App, id string, interfaces []Interface, current func() bool) bool {
	s.mutations.Lock()
	defer s.mutations.Unlock()
	if parent.Err() != nil || !current() {
		return false
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	pending, err := hasBindingRename(ctx, app, id)
	if err != nil {
		if parent.Err() == nil {
			app.Logger().Error("Could not verify the DDNS rename fence.")
		}
		return true
	}
	if pending {
		return true
	}
	var b Binding
	err = app.DB().Select("*").From("ddns_bindings").Where(dbx.HashExp{"id": id}).WithContext(ctx).One(&b)
	if err == nil {
		s.syncBinding(ctx, app, b, findInterface(interfaces, b.InterfaceName), current)
	} else if !errors.Is(err, sql.ErrNoRows) && parent.Err() == nil {
		app.Logger().Error("Could not reload a DDNS binding for synchronization.")
	}
	return true
}

func (s *Service) syncBinding(ctx context.Context, app core.App, b Binding, iface *Interface, current func() bool) {
	preferred := selectAddress(iface, b.RecordType, b.LastAddress)
	if !preferred.IsValid() {
		if b.SyncStatus != "waiting" {
			s.saveSync(app, b, b.RecordID, b.LastAddress, "waiting", "No eligible address on the selected interface.", "", 0)
		}
		return
	}
	checkedAt, _ := time.Parse(time.RFC3339, b.UpdatedAt)
	since := s.now().Sub(checkedAt)
	if b.SyncStatus == "synced" && preferred.String() == b.LastAddress && since < reconcileInterval {
		return
	}
	failures := 0
	if b.SyncStatus == "failed" && preferred.String() == b.AttemptedAddress {
		if since < retryDelay(b.FailureCount) {
			return
		}
		failures = b.FailureCount
	}
	fail := func(message string) {
		if current() {
			s.saveSync(app, b, b.RecordID, b.LastAddress, "failed", message, preferred.String(), min(failures+1, maxFailedAttempts))
		}
	}
	scopeValid := func() bool {
		if ctx.Err() != nil {
			return false
		}
		zone, err := dnscatalog.LookupZone(app, b.Provider, b.AccessID, b.ZoneID)
		return err == nil && sameOwner(b.ZoneName, zone.Name)
	}
	if !scopeValid() {
		fail("DNS account or zone is unavailable.")
		return
	}
	p, err := s.resolve(ctx, b.Provider, b.AccessID, b.ZoneID)
	editor, ok := p.(dns.RecordEditor)
	if err != nil || !ok {
		fail("Could not open the DNS provider for verified updates.")
		return
	}

	original, err := lookupRecord(ctx, p, b.ZoneID, b.RecordID)
	switch {
	case errors.Is(err, errRecordMissing):
		fail("The bound DNS record no longer exists.")
		return
	case err != nil:
		fail("Could not read the bound DNS record.")
		return
	case !bindableRecord(original, b.ZoneName) || !sameOwner(original.Name, b.RecordName) || !strings.EqualFold(original.Type, b.RecordType):
		fail("The bound DNS record's owner, type or writability changed.")
		return
	}

	wanted := selectAddress(iface, b.RecordType, original.Content, b.LastAddress)
	if actual, _ := netip.ParseAddr(original.Content); actual == wanted {
		s.saveSync(app, b, b.RecordID, wanted.String(), "synced", "", "", 0)
		return
	}
	desired := dns.RecordInput{
		Name: original.Name, Type: original.Type, Content: wanted.String(), TTL: original.TTL,
		Line: original.Line, Description: original.Description, Weight: original.Weight,
	}
	writer := snapshotWriter{Provider: p, RecordEditor: editor, canSubmit: func() bool { return current() && scopeValid() }}
	newID, err := dns.ReplaceVerified(ctx, writer, b.ZoneID, b.ZoneName, *original, desired, scopeValid)
	if err != nil {
		fail("Could not confirm the DNS update. The provider will be read again before retrying.")
		return
	}
	s.saveSync(app, b, newID, wanted.String(), "synced", "", "", 0)
}

func (s *Service) saveSync(app core.App, b Binding, recordID, address, status, message, attempted string, failures int) {
	_, err := app.DB().Update("ddns_bindings", dbx.Params{
		"record_id": recordID, "last_address": address, "sync_status": status, "last_error": message,
		"updated_at": s.now().UTC().Format(time.RFC3339), "attempted_address": attempted, "failure_count": failures,
	}, dbx.HashExp{"id": b.ID, "record_id": b.RecordID}).Execute()
	if err != nil {
		app.Logger().Error("Could not persist the DDNS synchronization result.")
	}
}
