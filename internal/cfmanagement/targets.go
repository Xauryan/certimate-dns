package cfmanagement

import (
	"strings"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/domain"
)

type Target struct {
	Zone     string `db:"zone" json:"zone"`
	ZoneID   string `db:"zoneId" json:"zoneId"`
	AccessID string `db:"accessId" json:"accessId"`
	Account  string `db:"account" json:"account"`
	Provider string `db:"provider" json:"provider"`
	Owner    string `json:"owner"`
}

// Resolve DNS-01 TXT owners against the longest live catalog zone. A name can
// have equal-length matches on multiple accounts during a DNS migration.
func targetZones(e *core.RequestEvent, raw string) ([]Target, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if !e.HasSuperuserAuth() {
		return nil, domain.NewError(403, "administrator required")
	}
	if len(name) > 253 || !strings.Contains(name, ".") {
		return nil, domain.ErrInvalidParams
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return nil, domain.ErrInvalidParams
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return nil, domain.ErrInvalidParams
			}
		}
	}
	const query = `WITH matching AS (
      SELECT z.providerZoneId AS zoneId, z.name AS zone, d.id AS accessId, a.name AS account, a.provider
      FROM dnsZone z JOIN dnsAccount d ON d.id=z.accountRef AND d.disabled=0
      JOIN access a ON a.id=d.id AND a.id=d.accessRef AND a.deleted=''
      WHERE z.present=1 AND (lower(z.name)={:name} OR substr({:name},-length(z.name)-1)='.'||lower(z.name))
    ) SELECT * FROM matching WHERE length(zone)=(SELECT max(length(zone)) FROM matching)
      ORDER BY provider,account,accessId`
	targets := []Target{}
	err := e.App.DB().NewQuery(query).Bind(dbx.Params{"name": name}).WithContext(e.Request.Context()).All(&targets)
	if err != nil {
		return nil, domain.NewError(500, "could not resolve verification targets")
	}
	for i := range targets {
		t := &targets[i]
		if strings.EqualFold(name, t.Zone) {
			t.Owner = "@"
		} else {
			t.Owner = strings.TrimSuffix(name, "."+strings.ToLower(t.Zone))
		}
	}
	return targets, nil
}
