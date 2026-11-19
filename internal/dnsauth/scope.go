// Package dnsauth resolves DNS authorization against the live member, grants,
// catalog and account state. Callers use local zone IDs or the complete
// provider/access/zone tuple, never a provider zone ID alone.
package dnsauth

import (
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

const Members = "dns_members"
const ZoneSessions = "dns_zone_sessions"

type Zone struct {
	ID                string `db:"id" json:"id"`
	AccessID          string `db:"accessId" json:"accessId"`
	Provider          string `db:"provider" json:"provider"`
	ZoneID            string `db:"zoneId" json:"zoneId"`
	Name              string `db:"name" json:"name"`
	Status            string `db:"status" json:"status"`
	CanWrite          bool   `db:"canWrite" json:"canWrite"`
	QuickLoginEnabled bool   `db:"quickLoginEnabled" json:"quickLoginEnabled"`
}

var supportedProviders = func() string {
	data, _ := json.Marshal(dns.SupportedProviders())
	return string(data)
}()

const liveZones = ` FROM dnsZone z
	JOIN dnsAccount a ON a.id = z.accountRef AND a.disabled = 0
	JOIN access c ON c.id = a.accessRef AND c.id = a.id AND c.deleted = ''
	AND c.provider IN (SELECT value FROM json_each({:providers}))`

// A zone can have multiple paths to the same member, with independent roles.
// Reduce those paths before counting zones or selecting a page.
const memberGrants = `WITH grants AS (
	SELECT zone, role FROM dns_zone_grants WHERE member = {:member}
	UNION ALL
	SELECT link.zone, grant_.role FROM dns_workspace_grants grant_
	JOIN dns_workspace_zones link ON link.workspace = grant_.workspace
	WHERE grant_.member = {:member}
), rights AS (
	SELECT zone, MAX(role = 'editor') AS writable FROM grants GROUP BY zone
)`

func scope(e *core.RequestEvent) (string, dbx.Params, error) {
	if e.Auth != nil && e.Auth.Collection().Name == ZoneSessions {
		return delegatedScope(e)
	}
	return ownerScope(e.Auth)
}

func ownerScope(owner *core.Record) (string, dbx.Params, error) {
	if owner == nil {
		return "", nil, domain.NewError(401, "authentication required")
	}
	columns := "SELECT z.id, c.id AS accessId, c.provider, z.providerZoneId AS zoneId, z.name, z.status, z.quickLoginEnabled, "
	if owner.IsSuperuser() {
		return columns + "1 AS canWrite" + liveZones + " WHERE z.present = 1", dbx.Params{"providers": supportedProviders}, nil
	}
	if owner.Collection().Name != Members || owner.GetBool("disabled") {
		return "", nil, domain.NewError(403, "DNS member access denied")
	}
	query := memberGrants + columns + "rights.writable AS canWrite" + liveZones +
		` JOIN rights ON rights.zone = z.id
		JOIN dns_members m ON m.id = {:member} AND m.disabled = 0
		WHERE z.present = 1`
	return query, dbx.Params{"member": owner.Id, "providers": supportedProviders}, nil
}

// ListZones scopes the count and the page to exactly the same set.
func ListZones(e *core.RequestEvent, page, perPage int) ([]Zone, int, error) {
	if page < 1 || page > 10000000 || perPage < 1 || perPage > 100 {
		return nil, 0, domain.ErrInvalidParams
	}
	query, params, err := scope(e)
	if err != nil {
		return nil, 0, err
	}
	if e.Auth.Collection().Name == Members {
		query = "SELECT * FROM (" + query + ") WHERE id IN (SELECT id FROM dnsZone WHERE hidden = 0)"
	}
	ctx := e.Request.Context()
	var total int
	if err := e.App.DB().NewQuery("SELECT COUNT(*) FROM (" + query + ")").Bind(params).WithContext(ctx).Row(&total); err != nil {
		return nil, 0, domain.NewError(500, "could not count DNS zones")
	}
	params["limit"] = perPage
	params["offset"] = (page - 1) * perPage
	zones := []Zone{}
	if err := e.App.DB().NewQuery("SELECT * FROM (" + query + ") ORDER BY name, id LIMIT {:limit} OFFSET {:offset}").
		Bind(params).WithContext(ctx).All(&zones); err != nil {
		return nil, 0, domain.NewError(500, "could not list DNS zones")
	}
	return zones, total, nil
}

func find(e *core.RequestEvent, filter string, values dbx.Params, write bool) (Zone, error) {
	var z Zone
	query, params, err := scope(e)
	if err != nil {
		return z, err
	}
	for k, v := range values {
		params[k] = v
	}
	err = e.App.DB().NewQuery("SELECT * FROM (" + query + ") WHERE " + filter).
		Bind(params).WithContext(e.Request.Context()).One(&z)
	if errors.Is(err, sql.ErrNoRows) {
		return Zone{}, domain.ErrRecordNotFound
	}
	if err != nil {
		return Zone{}, domain.NewError(500, "could not resolve DNS authorization")
	}
	if write && !z.CanWrite {
		return Zone{}, domain.NewError(403, "read-only DNS access")
	}
	return z, nil
}

func GetZone(e *core.RequestEvent, id string, write bool) (Zone, error) {
	return find(e, "id = {:id}", dbx.Params{"id": id}, write)
}

func FindZone(e *core.RequestEvent, provider, accessID, providerZoneID string, write bool) (Zone, error) {
	return find(e, "provider = {:provider} AND accessId = {:access} AND zoneId = {:zone}",
		dbx.Params{"provider": provider, "access": accessID, "zone": providerZoneID}, write)
}

func RequireZone(e *core.RequestEvent, provider, accessID, providerZoneID string, write bool) error {
	_, err := FindZone(e, provider, accessID, providerZoneID, write)
	return err
}
