package dnsmcp

import (
	"context"
	"slices"
	"strings"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnsauth"
	cf "github.com/certimate-go/certimate/pkg/sdk3rd/cloudflare"
)

// A grant on a parent zone cannot authorize a delegated child zone. Determine the
// most-specific live match in this credential's catalog before checking the key.
func cfPublishedZone(e *core.RequestEvent, grant scope, access, hostname string, write bool) (dnsauth.Zone, *opError) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	if name == "" {
		return dnsauth.Zone{}, invalid
	}
	var matches []struct {
		ID   string `db:"id"`
		Name string `db:"name"`
	}
	err := e.App.DB().NewQuery(`SELECT id, lower(rtrim(name,'.')) AS name FROM dnsZone
		WHERE present=1 AND accountRef={:a} AND (lower(rtrim(name,'.'))={:h} OR
		substr({:h}, -length(rtrim(name,'.'))-1)='.'||lower(rtrim(name,'.')))
		ORDER BY length(rtrim(name,'.')) DESC,id LIMIT 2`).Bind(dbx.Params{"a": access, "h": name}).WithContext(e.Request.Context()).All(&matches)
	if err != nil {
		return dnsauth.Zone{}, upstream
	}
	if len(matches) == 0 || (len(matches) == 2 && matches[0].Name == matches[1].Name) || !slices.Contains(grant.Zones, matches[0].ID) {
		return dnsauth.Zone{}, missing
	}
	z, err := dnsauth.GetZone(e, matches[0].ID, write)
	if err != nil || z.AccessID != access || z.Provider != "cloudflare" {
		return dnsauth.Zone{}, missing
	}
	return z, nil
}

func (s service) cfZoneReader(ctx context.Context, access string) (*cf.Client, *opError) {
	p, err := s.resolve(ctx, "cloudflare", access, true)
	if err != nil {
		return nil, missing
	}
	c, ok := p.(*cf.Client)
	if !ok || c == nil {
		return nil, unsupported
	}
	return c, nil
}

func (s service) cfTunnel(e *core.RequestEvent, c *cf.Client, grant scope, access, account, action string, args object) (object, *opError) {
	ctx := e.Request.Context()
	tunnel := str(args, "tunnel_id")
	hostname := str(args, "hostname")
	switch action {
	case "list":
		return cfList(ctx, args, func(ctx context.Context, page int) (*cf.DNSPage[cf.Tunnel], error) {
			return c.Tunnels(ctx, account, page)
		})
	case "add":
		return cfResult(c.CreateTunnel(ctx, account, str(args, "name")))
	case "delete":
		return cfResult(nil, c.DeleteTunnel(ctx, account, tunnel))
	case "token":
		token, err := c.EncryptedTunnelToken(ctx, account, tunnel, str(args, "recipient_public_key"))
		return cfResult(object{"encrypted_token": token}, err)
	case "public_hostnames":
		config, err := c.PublishedRoutes(ctx, account, tunnel)
		if err != nil {
			return cfResult(nil, err)
		}
		rows := []object{}
		for _, r := range config.Rules {
			z, problem := cfPublishedZone(e, grant, access, r.Hostname, false)
			if problem == missing {
				continue
			}
			if problem != nil {
				return nil, problem
			}
			rows = append(rows, object{"hostname": r.Hostname, "path": r.Path, "service": r.Service, "zone_name": z.Name, "zone_id": z.ZoneID, "domain_id": z.ID})
		}
		return object{"code": 0, "rows": rows, "total": len(rows), "version": config.Version}, nil
	case "public_hostname_save", "public_hostname_delete":
		z, problem := cfPublishedZone(e, grant, access, hostname, true)
		if problem != nil {
			return nil, problem
		}
		reader, problem := s.cfZoneReader(ctx, access)
		if problem != nil {
			return nil, problem
		}
		config, err := c.PublishedRoutes(ctx, account, tunnel)
		if err != nil {
			return cfResult(nil, err)
		}
		in := cf.IngressChange{Zone: z.ZoneID, Version: config.Version, IngressRule: cf.IngressRule{Hostname: hostname, Path: str(args, "path"), Service: str(args, "service")}}
		return cfResult(nil, c.ChangeIngressWithZoneReader(ctx, account, tunnel, in, action == "public_hostname_delete", reader))
	case "cidr_routes", "hostname_routes":
		kind := strings.TrimSuffix(action, "_routes")
		return cfList(ctx, args, func(ctx context.Context, page int) (*cf.DNSPage[cf.Route], error) {
			return c.TunnelRoutes(ctx, account, tunnel, kind, page)
		})
	case "cidr_add", "hostname_route_add":
		kind, value := "cidr", str(args, "network")
		if action == "hostname_route_add" {
			kind, value = "hostname", hostname
		}
		return cfResult(c.AddRoute(ctx, account, tunnel, kind, cf.RouteInput{Value: value, Comment: str(args, "comment")}))
	case "cidr_delete", "hostname_route_delete":
		kind := "cidr"
		if action == "hostname_route_delete" {
			kind = "hostname"
		}
		return cfResult(nil, c.DeleteRoute(ctx, account, tunnel, kind, str(args, "route_id")))
	default:
		return nil, invalid
	}
}
