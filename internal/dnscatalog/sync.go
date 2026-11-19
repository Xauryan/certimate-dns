package dnscatalog

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"golang.org/x/net/idna"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

var syncing sync.Map

func liveAccount(app core.App, id string) (*Account, error) {
	a, err := account(app, id)
	if err != nil {
		return nil, err
	}
	if !a.Enabled {
		return nil, domain.NewError(409, "DNS account is disabled")
	}
	return a, nil
}

func validZone(z dns.Zone) bool {
	return z.ID != "" && utf8.RuneCountInString(z.ID) <= 255 && strings.IndexFunc(z.ID, unicode.IsControl) < 0 && z.Name != "" && utf8.RuneCountInString(z.Name) <= 253 && strings.IndexFunc(z.Name, unicode.IsControl) < 0 && utf8.RuneCountInString(z.Status) <= 128
}

func discover(ctx context.Context, client dns.Provider, page int) (*dns.DNSPage[dns.Zone], error) {
	rows, err := client.Zones(ctx, page)
	if err != nil {
		return nil, err
	}
	if rows == nil || rows.Info.Page != page || rows.Info.Total < len(rows.Items) {
		return nil, domain.NewError(502, "invalid DNS provider inventory")
	}
	for i := range rows.Items {
		z := &rows.Items[i]
		z.Name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z.Name)), ".")
		if !validZone(*z) {
			return nil, domain.NewError(502, "invalid DNS provider zone")
		}
	}
	return rows, nil
}

func Discover(ctx context.Context, app core.App, accountID string, page int, resolve Resolve) (*dns.DNSPage[dns.Zone], error) {
	if page < 1 || page > 10000000 {
		return nil, domain.ErrInvalidParams
	}
	a, err := liveAccount(app, accountID)
	if err != nil {
		return nil, err
	}
	client, err := resolve(ctx, a.Provider, accountID, true)
	if err != nil {
		return nil, err
	}
	return discover(ctx, client, page)
}

// syncAccount reconciles a complete provider inventory. Selective import never
// changes the presence status of an unselected zone.
func syncAccount(ctx context.Context, app core.App, id string, resolve Resolve) (int, error) {
	return syncZones(ctx, app, id, nil, resolve)
}

func ImportZones(ctx context.Context, app core.App, accountID string, ids []string, resolve Resolve) (int, error) {
	if len(ids) == 0 || len(ids) > 500 {
		return 0, domain.ErrInvalidParams
	}
	selected := map[string]bool{}
	for _, id := range ids {
		if id == "" || selected[id] {
			return 0, domain.ErrInvalidParams
		}
		selected[id] = true
	}
	return syncZones(ctx, app, accountID, selected, resolve)
}

func syncZones(ctx context.Context, app core.App, id string, selected map[string]bool, resolve Resolve) (int, error) {
	a, err := liveAccount(app, id)
	if err != nil {
		return 0, err
	}
	if _, busy := syncing.LoadOrStore(id, struct{}{}); busy {
		return 0, domain.NewError(409, "account sync in progress")
	}
	defer syncing.Delete(id)
	client, err := resolve(ctx, a.Provider, id, true)
	if err != nil {
		return 0, err
	}
	snapshot := map[string]dns.Zone{}
	total := -1
	inconsistent := domain.NewError(502, "incomplete zone inventory; refresh and retry")
	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		rows, err := discover(ctx, client, page)
		if err != nil {
			return 0, err
		}
		if total >= 0 && total != rows.Info.Total {
			return 0, inconsistent
		}
		total = rows.Info.Total
		for _, z := range rows.Items {
			if _, ok := snapshot[z.ID]; ok {
				return 0, inconsistent
			}
			snapshot[z.ID] = z
		}
		if len(snapshot) == total {
			break
		}
		if len(rows.Items) == 0 || len(snapshot) > total {
			return 0, inconsistent
		}
	}
	if selected != nil {
		for id := range selected {
			if _, ok := snapshot[id]; !ok {
				return 0, domain.ErrRecordNotFound
			}
		}
		for id := range snapshot {
			if !selected[id] {
				delete(snapshot, id)
			}
		}
	}
	err = app.RunInTransaction(func(tx core.App) error {
		if err := checkAccount(tx, a); err != nil {
			return err
		}
		if selected == nil {
			var present []struct {
				ID     string `db:"id"`
				ZoneID string `db:"providerZoneId"`
			}
			if err := tx.DB().NewQuery("SELECT id,providerZoneId FROM dnsZone WHERE accountRef={:account} AND present=1").Bind(dbx.Params{"account": id}).WithContext(ctx).All(&present); err != nil {
				return err
			}
			for _, r := range present {
				if _, ok := snapshot[r.ZoneID]; !ok {
					if _, err := tx.DB().NewQuery("UPDATE dnsZone SET present=0 WHERE id={:id}").Bind(dbx.Params{"id": r.ID}).WithContext(ctx).Execute(); err != nil {
						return err
					}
				}
			}
		}
		for _, z := range snapshot {
			if _, err := saveZone(ctx, tx, id, z); err != nil {
				return err
			}
		}
		return ctx.Err()
	})
	return len(snapshot), err
}

func checkAccount(app core.App, a *Account) error {
	current, err := liveAccount(app, a.ID)
	if err != nil {
		return err
	}
	if current.Provider != a.Provider {
		return domain.NewError(409, "DNS provider changed during sync")
	}
	_, err = EnsureAccount(app, a.ID)
	return err
}

func saveZone(ctx context.Context, tx core.App, accountID string, z dns.Zone) (string, error) {
	c, err := tx.FindCollectionByNameOrId("dnsZone")
	if err != nil {
		return "", err
	}
	r, err := tx.FindFirstRecordByFilter(c, "accountRef={:account} && providerZoneId={:zone}", dbx.Params{"account": accountID, "zone": z.ID})
	if errors.Is(err, sql.ErrNoRows) {
		r = core.NewRecord(c)
		r.Set("accountRef", accountID)
		r.Set("providerZoneId", z.ID)
		r.Set("tags", []string{})
		r.Set("reminderDays", 30)
	} else if err != nil {
		return "", err
	} else if r.GetBool("present") && r.GetString("name") == z.Name && r.GetString("status") == z.Status {
		return r.Id, nil
	}
	r.Set("present", true)
	r.Set("name", z.Name)
	r.Set("status", z.Status)
	err = tx.SaveWithContext(ctx, r)
	return r.Id, err
}

func CreateZone(ctx context.Context, app core.App, accountID, name string, resolve Resolve) (*Domain, error) {
	name, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), "."))
	if err != nil || !strings.Contains(name, ".") || len(name) > 253 || strings.ContainsAny(name, "/:@[]") {
		return nil, domain.ErrInvalidParams
	}
	a, err := liveAccount(app, accountID)
	if err != nil {
		return nil, err
	}
	if _, busy := syncing.LoadOrStore(accountID, struct{}{}); busy {
		return nil, domain.NewError(409, "account sync in progress")
	}
	defer syncing.Delete(accountID)
	var count int
	if err := app.DB().NewQuery("SELECT count(*) FROM dnsZone WHERE accountRef={:account} AND lower(name)={:name} AND present=1").Bind(dbx.Params{"account": accountID, "name": name}).WithContext(ctx).Row(&count); err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, domain.NewError(409, "domain already exists in catalog")
	}
	client, err := resolve(ctx, a.Provider, accountID, false)
	if err != nil {
		return nil, err
	}
	creator, ok := client.(dns.ZoneCreator)
	if !ok {
		return nil, domain.NewError(422, "provider does not support creating zones")
	}
	z, err := creator.CreateZone(ctx, name)
	if err != nil {
		return nil, domain.NewError(502, "zone creation could not be confirmed; discover zones before retrying")
	}
	if z == nil || !validZone(*z) || !strings.EqualFold(strings.TrimSuffix(z.Name, "."), name) {
		return nil, domain.NewError(502, "invalid response to zone creation; discover zones before retrying")
	}
	z.Name = name
	var result *Domain
	err = app.RunInTransaction(func(tx core.App) error {
		if err := checkAccount(tx, a); err != nil {
			return err
		}
		id, err := saveZone(ctx, tx, accountID, *z)
		if err != nil {
			return err
		}
		result, err = Lookup(tx, id)
		return err
	})
	if err != nil {
		return nil, domain.NewError(409, "provider created the zone; discover it to complete import")
	}
	return result, nil
}
