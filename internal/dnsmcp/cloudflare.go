package dnsmcp

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnsauth"
	cf "github.com/certimate-go/certimate/pkg/sdk3rd/cloudflare"
)

var cfTools = []toolDefinition{
	{"cf_hostname_query", "Inspect Cloudflare for SaaS hostnames and validation in a granted local zone.", []operation{
		{"list", "cf.hostname.read"}, {"txt_targets", "cf.hostname.read"}, {"fallback_get", "cf.hostname.read"}, {"dcv_uuid", "cf.hostname.read"},
	}, []string{"domain_id", "hostname", "page"}},
	{"cf_hostname_manage", "Manage Cloudflare for SaaS hostnames and the fallback origin in a granted local zone.", []operation{
		{"add", "cf.hostname.add"}, {"batch_add", "cf.hostname.add"}, {"update", "cf.hostname.update"}, {"batch_update", "cf.hostname.update"},
		{"refresh", "cf.hostname.refresh"}, {"delete", "cf.hostname.delete"}, {"batch_delete", "cf.hostname.delete"},
		{"fallback_set", "cf.fallback.set"}, {"fallback_delete", "cf.fallback.delete"},
	}, []string{"domain_id", "hostname", "hostnames", "hostname_id", "hostname_ids", "custom_origin_server", "ssl_method", "min_tls_version", "origin"}},
	{"cf_tunnel_query", "Inspect tunnels in an explicitly granted local Cloudflare account. Token export requires a recipient public key.", []operation{
		{"list", "cf.tunnel.read"}, {"token", "cf.tunnel.token.read"}, {"public_hostnames", "cf.tunnel.read"}, {"cidr_routes", "cf.tunnel.read"}, {"hostname_routes", "cf.tunnel.read"},
	}, []string{"account_id", "domain_id", "tunnel_id", "page", "recipient_public_key"}},
	{"cf_tunnel_manage", "Manage a granted Cloudflare account's tunnels and routes. Published hostname changes also require a grant on the matching DNS zone.", []operation{
		{"add", "cf.tunnel.add"}, {"delete", "cf.tunnel.delete"}, {"public_hostname_save", "cf.tunnel.publish"}, {"public_hostname_delete", "cf.tunnel.unpublish"},
		{"cidr_add", "cf.tunnel.route.add"}, {"cidr_delete", "cf.tunnel.route.delete"}, {"hostname_route_add", "cf.tunnel.route.add"}, {"hostname_route_delete", "cf.tunnel.route.delete"},
	}, []string{"account_id", "domain_id", "tunnel_id", "name", "hostname", "service", "path", "network", "comment", "route_id"}},
}

func cfResult(data any, err error) (object, *opError) {
	switch {
	case err == nil:
		return object{"code": 0, "msg": "OK", "data": data}, nil
	case errors.Is(err, cf.ErrInvalidDNSRequest):
		return nil, invalid
	case errors.Is(err, cf.ErrConfigChanged):
		return nil, &opError{409, "Cloudflare configuration changed; reload before editing"}
	default:
		return nil, upstream
	}
}

// The Cloudflare token may see multiple accounts. Never trust a caller's native account or
// zone identifier; resolve identifiers using the granted local catalog and live actor rights.
func (s service) executeCF(e *core.RequestEvent, tool, action string, args object, grant scope) (out object, problem *opError) {
	if !e.HasSuperuserAuth() {
		return nil, denied
	}
	// An object or null in place of a string must not silently clear an origin or path.
	for name, value := range args {
		switch name {
		case "hostnames", "hostname_ids":
			if _, ok := cfStrings(value); !ok {
				return nil, invalid
			}
		case "page":
			if _, ok := number(args, name, 0, 1, 10000000); !ok {
				return nil, invalid
			}
		case "account_id", "domain_id":
			if str(args, name) == "" {
				return nil, invalid
			}
		default:
			if _, ok := value.(string); !ok {
				return nil, invalid
			}
		}
	}
	if strings.HasSuffix(tool, "_manage") || action == "token" {
		defer func() {
			e.App.Logger().Info("DNS interface Cloudflare operation", "actor", e.Auth.Id, "tool", tool, "action", action, "success", problem == nil)
		}()
	}
	var z dnsauth.Zone
	var err error
	access := str(args, "account_id")
	if tool == "cf_hostname_query" || tool == "cf_hostname_manage" {
		id := str(args, "domain_id")
		if id == "" || !slices.Contains(grant.Zones, id) {
			return nil, missing
		}
		z, err = dnsauth.GetZone(e, id, tool == "cf_hostname_manage")
		if err != nil || z.Provider != "cloudflare" {
			return nil, missing
		}
		access = z.AccessID
		if action == "txt_targets" {
			return cfTXTTargets(e, grant, z, args)
		}
	} else if tool == "cf_tunnel_query" || tool == "cf_tunnel_manage" {
		if access == "" || !slices.Contains(grant.Accounts, access) {
			return nil, denied
		}
	} else {
		return nil, invalid
	}
	provider, err := s.resolve(e.Request.Context(), "cloudflare", access, false)
	if err != nil {
		return nil, missing
	}
	client, ok := provider.(*cf.Client)
	if !ok || client == nil {
		return nil, unsupported
	}
	if z.ID != "" {
		return cfHostname(e, client, z, action, args)
	}
	account, problem := s.cfAccount(e, client, access, grant, args)
	if problem != nil {
		return nil, problem
	}
	return s.cfTunnel(e, client, grant, access, account, action, args)
}

func (s service) cfAccount(e *core.RequestEvent, client *cf.Client, access string, grant scope, args object) (string, *opError) {
	record, err := e.App.FindRecordById("access", access)
	if err != nil || record.GetString("deleted") != "" || record.GetString("provider") != "cloudflare" {
		return "", missing
	}
	var config struct {
		AccountID string `json:"accountId"`
		LegacyID  string `json:"account_id"`
	}
	if record.UnmarshalJSONField("config", &config) != nil {
		return "", invalid
	}
	bound := config.AccountID
	if bound == "" {
		bound = config.LegacyID
	}

	if id := str(args, "domain_id"); id != "" {
		if !slices.Contains(grant.Zones, id) {
			return "", missing
		}
		z, err := dnsauth.GetZone(e, id, false)
		if err != nil || z.AccessID != access || z.Provider != "cloudflare" {
			return "", missing
		}
		reader, problem := s.cfZoneReader(e.Request.Context(), access)
		if problem != nil {
			return "", problem
		}
		account, err := reader.ZoneAccount(e.Request.Context(), z.ZoneID)
		if err != nil {
			return "", upstream
		}
		if bound != "" && account.ID != bound {
			return "", missing
		}
		return account.ID, nil
	}
	if bound != "" {
		return bound, nil
	}

	p, err := client.Accounts(e.Request.Context(), 1)
	if err != nil || p == nil {
		return "", upstream
	}
	if p.Info.Total != 1 || len(p.Items) != 1 {
		return "", &opError{422, "Specify a granted domain_id to select its Cloudflare account"}
	}
	return p.Items[0].ID, nil
}

func cfList[T any](ctx context.Context, args object, fetch func(context.Context, int) (*cf.DNSPage[T], error)) (object, *opError) {
	requested, ok := number(args, "page", 0, 1, 10000000)
	if !ok {
		return nil, invalid
	}
	rows := []T{}
	total := -1
	for page := max(requested, 1); ; page++ {
		p, err := fetch(ctx, page)
		if err != nil || p == nil || p.Info.Page != page || p.Info.Total < 0 || (total >= 0 && total != p.Info.Total) {
			return nil, upstream
		}
		total = p.Info.Total
		if len(p.Items) != min(cf.DNSPageSize, max(0, total-(page-1)*cf.DNSPageSize)) {
			return nil, upstream
		}
		if requested == 0 && total > 10000 {
			return nil, &opError{422, "Specify page for Cloudflare lists larger than 10000 rows"}
		}
		rows = append(rows, p.Items...)
		if requested > 0 || len(rows) >= total {
			break
		}
	}
	return object{"code": 0, "total": total, "rows": rows}, nil
}
