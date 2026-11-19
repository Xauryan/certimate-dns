package dnsmcp

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/domain"
	cf "github.com/certimate-go/certimate/pkg/sdk3rd/cloudflare"
)

func cfHostname(e *core.RequestEvent, c *cf.Client, z dnsauth.Zone, action string, args object) (object, *opError) {
	ctx := e.Request.Context()
	id := str(args, "hostname_id")
	switch action {
	case "list":
		return cfList(ctx, args, func(ctx context.Context, page int) (*cf.DNSPage[object], error) {
			p, err := c.Hostnames(ctx, z.ZoneID, page)
			if err != nil || p == nil {
				return nil, err
			}
			out := &cf.DNSPage[object]{Info: p.Info}
			for _, h := range p.Items {
				out.Items = append(out.Items, cfHostnameRow(h))
			}
			return out, nil
		})
	case "fallback_get", "fallback_set", "fallback_delete":
		method := map[string]string{"fallback_get": http.MethodGet, "fallback_set": http.MethodPut, "fallback_delete": http.MethodDelete}[action]
		origin, err := c.FallbackOrigin(ctx, z.ZoneID, method, str(args, "origin"))
		return cfResult(origin, err)
	case "dcv_uuid":
		return cfResult(c.Delegation(ctx, z.ZoneID))
	case "refresh":
		h, err := c.RevalidateHostname(ctx, z.ZoneID, id)
		return cfResult(cfHostnameRow(h), err)
	case "delete":
		return cfResult(nil, c.DeleteHostname(ctx, z.ZoneID, id))
	case "add", "update", "batch_add", "batch_update", "batch_delete":
	default:
		return nil, invalid
	}
	origin := str(args, "custom_origin_server")
	in := cf.HostnameInput{Origin: &origin, Method: str(args, "ssl_method"), MinTLS: str(args, "min_tls_version")}
	if action != "batch_update" {
		if in.Method == "" {
			in.Method = "txt"
		}
		if in.MinTLS == "" {
			in.MinTLS = "1.0"
		}
	}
	switch action {
	case "add":
		in.Hostname = str(args, "hostname")
		h, err := c.SaveHostname(ctx, z.ZoneID, "", in)
		return cfResult(cfHostnameRow(h), err)
	case "update":
		if id == "" {
			return nil, invalid
		}
		h, err := c.SaveHostname(ctx, z.ZoneID, id, in)
		return cfResult(cfHostnameRow(h), err)
	}
	key := "hostname_ids"
	if action == "batch_add" {
		key = "hostnames"
	}
	items, ok := cfStrings(args[key])
	if !ok {
		return nil, invalid
	}
	for i, item := range items {
		live, err := dnsauth.GetZone(e, z.ID, true)
		if err != nil || live.AccessID != z.AccessID || live.ZoneID != z.ZoneID || live.Provider != "cloudflare" {
			return partial(i, len(items), "Domain grant or account changed")
		}
		switch action {
		case "batch_add":
			in.Hostname = item
			_, err = c.SaveHostname(ctx, z.ZoneID, "", in)
		case "batch_update":
			_, err = c.SaveHostname(ctx, z.ZoneID, item, in)
		case "batch_delete":
			err = c.DeleteHostname(ctx, z.ZoneID, item)
		}
		if err != nil {
			return partial(i, len(items), "Check Cloudflare state before retrying")
		}
	}
	return object{"code": 0, "msg": "OK", "completed": len(items)}, nil
}

func cfStrings(raw any) ([]string, bool) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 || len(values) > 100 {
		return nil, false
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		s, ok := v.(string)
		s = strings.TrimSpace(s)
		if !ok || s == "" || slices.Contains(out, s) {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func cfHostnameRow(h cf.Hostname) object {
	statuses := []string{}
	for _, r := range h.SSL.Records {
		if r.Status != "" && !slices.Contains(statuses, r.Status) {
			statuses = append(statuses, r.Status)
		}
	}
	validation := strings.Join(statuses, " / ")
	if validation == "" {
		validation = h.SSL.Status
	}
	return object{
		"id": h.ID, "hostname": h.Hostname, "custom_origin_server": h.Origin, "status": h.Status,
		"ssl": h.SSL, "ssl_status": h.SSL.Status, "ssl_method": h.SSL.Method, "ssl_min_tls_version": h.SSL.Settings.MinTLS,
		"ssl_type": h.SSL.Type, "ssl_validation_status": validation, "ssl_validation_records": h.SSL.Records,
		"ownership_verification": h.Ownership, "ownership_verification_http": h.OwnershipHTTP,
	}
}

func cfTXTTargets(e *core.RequestEvent, grant scope, current dnsauth.Zone, args object) (object, *opError) {
	raw := str(args, "hostname")
	name := strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), ".")), "*.")
	if name == "" || len(name) > 253 {
		return nil, invalid
	}
	candidates := []object{}
	add := func(z dnsauth.Zone, rr string) {
		candidates = append(candidates, object{"domain_id": z.ID, "domain_name": z.Name, "record_name": rr,
			"account_id": z.AccessID, "account_type": providerType(z.Provider), "is_current_domain": z.ID == current.ID})
	}
	longest := -1
	for _, id := range grant.Zones {
		z, err := dnsauth.GetZone(e, id, false)
		if errors.Is(err, domain.ErrRecordNotFound) {
			continue
		}
		if err != nil {
			return nil, missing
		}
		zone := strings.ToLower(strings.TrimSuffix(z.Name, "."))
		if zone == "" || (name != zone && !strings.HasSuffix(name, "."+zone)) || len(zone) < longest {
			continue
		}
		if len(zone) > longest {
			longest = len(zone)
			candidates = candidates[:0]
		}
		rr := "@"
		if name != zone {
			rr = strings.TrimSuffix(name, "."+zone)
		}
		add(z, rr)
	}
	if len(candidates) == 0 && !strings.Contains(name, ".") {
		add(current, name)
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a["is_current_domain"] != b["is_current_domain"] {
			return a["is_current_domain"].(bool)
		}
		return a["domain_id"].(string) < b["domain_id"].(string)
	})
	return cfResult(object{"hostname": raw, "candidates": candidates}, nil)
}
