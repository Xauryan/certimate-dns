package handlers

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/dnscatalog"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type recordUpdate struct {
	dns.RecordPatch
	Name     *string        `json:"name"`
	Type     *string        `json:"type"`
	Priority *int           `json:"priority"`
	Expected *dns.DNSRecord `json:"expected"`
}

// An administrator can also reach the editor through remote discovery before
// catalog synchronization. Re-read the selected provider page to resolve the
// authoritative zone name in that case; never accept an origin from a form.
func editZoneName(e *core.RequestEvent, p dns.Provider) (string, error) {
	provider, account, zone := e.Request.PathValue("provider"), e.Request.PathValue("access"), e.Request.PathValue("zone")
	z, err := dnsauth.FindZone(e, provider, account, zone, true)
	if err == nil {
		return z.Name, nil
	}
	if !e.HasSuperuserAuth() || !errors.Is(err, domain.ErrRecordNotFound) {
		return "", err
	}
	if details, ok := p.(interface {
		ZoneDetails(context.Context, string) (*dns.ZoneDetails, error)
	}); ok {
		d, err := details.ZoneDetails(e.Request.Context(), zone)
		if err != nil {
			return "", domain.NewError(502, "Could not confirm DNS zone")
		}
		if d != nil && d.Name != "" {
			return d.Name, nil
		}
	}
	page := 1
	if q := e.Request.URL.Query().Get("zonePage"); q != "" {
		page, err = strconv.Atoi(q)
		if err != nil || page < 1 || page > 10000000 {
			return "", domain.ErrInvalidParams
		}
	}
	result, err := p.Zones(e.Request.Context(), page)
	if err != nil || result == nil || result.Info.Page != page {
		return "", domain.NewError(502, "Could not confirm DNS zone")
	}
	for _, item := range result.Items {
		if item.ID == zone && item.Name != "" {
			return item.Name, nil
		}
	}
	return "", domain.ErrRecordNotFound
}

func replaceRecord(e *core.RequestEvent, p dns.Provider, id string, in recordUpdate) (string, error) {
	if _, ok := p.(dns.RecordEditor); !ok {
		return "", domain.NewError(422, "Provider cannot change record identity or priority")
	}
	if in.Expected == nil {
		return "", domain.NewError(400, "Record snapshot required for changes to name, type or priority")
	}
	provider, account, zone := e.Request.PathValue("provider"), e.Request.PathValue("access"), e.Request.PathValue("zone")
	if !liveRecordEditSession(e) || e.HasSuperuserAuth() && !liveEditAccount(e, account, provider) {
		return "", domain.NewError(403, "DNS editor access required")
	}
	name, err := editZoneName(e, p)
	if err != nil {
		return "", err
	}
	ctx := e.Request.Context()
	q := e.Request.URL.Query()
	page, err := pageNumber(e)
	if err != nil || len(q.Get("name")) > 253 {
		return "", domain.ErrInvalidParams
	}
	rows, err := p.DNSRecords(ctx, zone, page, q.Get("name"))
	if err != nil {
		return "", domain.NewError(502, "Could not read the selected DNS record")
	}
	if rows == nil || rows.Info.Page != page {
		return "", domain.ErrRecordNotFound
	}
	matched := slices.IndexFunc(rows.Items, func(r dns.DNSRecord) bool { return r.ID == id })
	if matched < 0 {
		return "", domain.ErrRecordNotFound
	}
	prior := rows.Items[matched]
	if !reflect.DeepEqual(*in.Expected, prior) {
		return "", domain.NewError(409, "The DNS record changed. Refresh before editing")
	}
	desired := dns.RecordInput{Name: prior.Name, Type: prior.Type, Content: in.Content, TTL: in.TTL, Line: prior.Line, Description: prior.Description, Weight: prior.Weight, Priority: prior.Priority}
	allowed, err := dns.RecordEditCapabilitiesForZone(ctx, p, zone)
	if err != nil {
		return "", domain.NewError(502, "Could not confirm DNS record capabilities")
	}
	if allowed == (dns.RecordEditCapabilities{}) {
		return "", domain.NewError(422, "Provider cannot change record identity or priority")
	}
	if in.Name != nil {
		if !allowed.Rename && !strings.EqualFold(*in.Name, prior.Name) {
			return "", domain.ErrInvalidParams
		}
		desired.Name = *in.Name
	}
	if in.Type != nil {
		if !allowed.Retype && *in.Type != prior.Type {
			return "", domain.ErrInvalidParams
		}
		desired.Type = *in.Type
	}
	caps, exists := dns.ProviderCapabilities(provider)
	if !exists || !caps.AllowsType(desired.Type) {
		return "", domain.ErrInvalidParams
	}
	hasPriority := slices.Contains(caps.PriorityTypes, desired.Type)
	if in.Priority != nil {
		if !hasPriority || !allowed.Priority || *in.Priority < 0 || *in.Priority > 65535 {
			return "", domain.ErrInvalidParams
		}
		desired.Priority = in.Priority
	} else if !hasPriority || desired.Type != prior.Type {
		desired.Priority = nil
	}
	if hasPriority && allowed.Priority && desired.Type != prior.Type && desired.Priority == nil {
		return "", domain.NewError(400, "Priority is required for the new record type")
	}
	authorized := func() bool {
		if !liveRecordEditSession(e) {
			return false
		}
		if e.HasSuperuserAuth() {
			return liveEditAccount(e, account, provider)
		}
		z, err := dnsauth.FindZone(e, provider, account, zone, true)
		return err == nil && strings.EqualFold(z.Name, name)
	}
	result, err := dns.ReplaceVerified(ctx, p, zone, name, prior, desired, authorized)
	switch {
	case err == nil:
		return result, nil
	case errors.Is(err, dns.ErrInvalidDNSRequest):
		return "", domain.ErrInvalidParams
	case errors.Is(err, dns.ErrRecordEditDenied):
		return "", domain.NewError(403, "DNS editor access required")
	case errors.Is(err, dns.ErrRecordEditConflict):
		return "", domain.NewError(409, "Record changed or overlaps the destination. Refresh before editing")
	case errors.Is(err, dns.ErrRecordEditUncertain):
		return "", domain.NewError(409, "Provider change could not be confirmed. Refresh records before retrying")
	default:
		return "", domain.NewError(502, "Provider record update failed")
	}
}

func liveRecordEditSession(e *core.RequestEvent) bool {
	current, err := e.App.FindRecordById(e.Auth.Collection().Name, e.Auth.Id)
	return err == nil && current.TokenKey() == e.Auth.TokenKey()
}

func liveEditAccount(e *core.RequestEvent, account, provider string) bool {
	enabled, err := dnscatalog.IsEnabled(e.App, account)
	if err != nil || !enabled {
		return false
	}
	current, err := e.App.FindRecordById("access", account)
	return err == nil && current.GetString("provider") == provider
}
