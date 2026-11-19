package dnsmigrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnsautomation"
	"github.com/certimate-go/certimate/internal/dnscatalog"
)

var ErrConflict = errors.New("resolve conflicts before importing; transaction not applied")

type Item struct {
	Category     string `json:"categoryId,omitempty"`
	categoryName string
	Kind         string `json:"kind"`
	Legacy       int64  `json:"legacyId"`
	Target       string `json:"targetId"`
	Action       string `json:"action"`
	Reason       string `json:"reason,omitempty"`
	AccountID    string `json:"accountId,omitempty"`
	ProviderZone string `json:"providerZoneId,omitempty"`
	digest       string
	details      any
	definition   *dnsautomation.Definition
}
type Report struct {
	Promotions []PromotionResult `json:"promotions,omitempty"`
	Version    int               `json:"version"`
	Source     string            `json:"source"`
	Items      []Item            `json:"items"`
	Conflicts  int               `json:"conflicts"`
	History    *HistoryCounts    `json:"historyCounts,omitempty"`
}

type planner struct {
	itemsByKey map[sourceKey]Item
	selected   map[sourceKey]string
	ctx        context.Context
	db         dbx.Builder
	manifest   *Manifest
	bindings   Bindings
	report     Report
}

func (p *planner) item(kind string, id int64, data any) Item {
	return Item{Kind: kind, Legacy: id, Target: targetID(p.manifest.Source, kind, id), details: data}
}
func (i *Item) conflict(why string) { i.Action = "conflict"; i.Reason = why }
func (p *planner) scalar(query string, args dbx.Params) (string, bool, error) {
	var s string
	err := p.db.NewQuery(query).Bind(args).WithContext(p.ctx).Row(&s)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return s, err == nil, err
}

// Reconcile the source and intended target identity with the first import.
// Replays never overwrite later edits or reactivate previously imported tasks.
func (p *planner) finish(i *Item, exists bool) error {
	i.digest = hash([]any{i.details, i.Target, i.AccountID, i.ProviderZone, p.manifest.Timezone})
	var saved struct {
		Digest      string `db:"digest"`
		Target      string `db:"target_id"`
		Disposition string `db:"disposition"`
	}
	err := p.db.NewQuery("SELECT digest,target_id,disposition FROM dns_import_items WHERE source={:s} AND kind={:k} AND legacy_id={:id}").Bind(dbx.Params{"s": p.manifest.Source, "k": i.Kind, "id": i.Legacy}).WithContext(p.ctx).One(&saved)
	switch {
	case err == nil && i.Action != "conflict":
		if row, ok := i.details.(Related); ok && row.Kind == "cert_account" && row.Provider != "" && saved.Disposition == "stage" && i.Action == "stage" && saved.Target == i.Target && saved.Digest != i.digest {
			// Earlier manifests omitted the credential-free certificate provider ID.
			// Only this additive enrichment of an otherwise identical staged row is permitted.
			row.Provider = ""
			if saved.Digest == hash([]any{row, i.Target, i.AccountID, i.ProviderZone, p.manifest.Timezone}) {
				i.Action = "refreshStage"
				i.Reason = "record certificate provider for reviewed mappings"
			} else {
				i.conflict("source or binding changed since first import")
			}
		} else if saved.Digest != i.digest || saved.Target != i.Target {
			i.conflict("source or binding changed since first import")
		} else if (saved.Disposition == "stage") != (i.Action == "stage") {
			i.conflict("previous mapping requires review")
		} else if !exists && saved.Disposition != "stage" {
			i.conflict("previous target is missing")
		} else {
			i.Action = "unchanged"
			i.Reason = saved.Disposition
		}
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return err
	}
	if i.Action == "conflict" {
		p.report.Conflicts++
	}
	p.report.Items = append(p.report.Items, *i)
	return nil
}

func Plan(ctx context.Context, db dbx.Builder, input *Manifest, b Bindings) (*Report, error) {
	copy := *input
	copy.Zones = slices.Clone(input.Zones)
	copy.Tasks = slices.Clone(input.Tasks)
	copy.Related = slices.Clone(input.Related)
	m := &copy
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if err := b.Validate(m); err != nil {
		return nil, err
	}
	p := &planner{ctx: ctx, db: db, manifest: m, bindings: b, report: Report{Version: Version, Source: m.Source, History: m.History, Items: []Item{}}}
	// An empty inventory must still target a migrated destination.
	if _, _, err := p.scalar("SELECT 1 FROM dns_import_items LIMIT 1", nil); err != nil {
		return nil, err
	}
	accounts := map[int64]Item{}
	bound := map[string]bool{}
	for _, a := range m.Accounts {
		i := p.item("account", a.ID, a)
		dest := b.Accounts[a.ID]
		provider := nativeProvider(a.Provider)
		exists := false
		switch {
		case provider == "":
			i.Action = "stage"
			i.Reason = "unsupported DNS provider"
			if dest != "" {
				i.conflict("binding for unsupported provider")
			}
		case !identifier.MatchString(dest):
			i.conflict("supply a compatible access ID in bindings")
		case bound[dest]:
			i.conflict("one access cannot represent multiple accounts in a source")
		default:
			bound[dest] = true
			i.Target = dest
			i.AccountID = dest
			found, ok, err := p.scalar("SELECT provider FROM access WHERE id={:id} AND deleted=''", dbx.Params{"id": dest})
			if err != nil {
				return nil, err
			}
			ref, linked, err := p.scalar("SELECT accessRef FROM dnsAccount WHERE id={:id}", dbx.Params{"id": dest})
			if err != nil {
				return nil, err
			}
			exists = linked
			switch {
			case !ok || found != provider:
				i.conflict("access missing, deleted or provider mismatch")
			case linked && ref != dest:
				i.conflict("account identity mismatch")
			case linked:
				i.Action = "reuse"
			default:
				i.Action = "link"
			}
		}
		if err := p.finish(&i, exists); err != nil {
			return nil, err
		}
		accounts[a.ID] = i
	}
	categories, err := p.categories()
	if err != nil {
		return nil, err
	}
	zones := map[int64]Item{}
	identities := map[[2]string]bool{}
	sourceZones := map[int64]Zone{}
	for _, z := range m.Zones {
		sourceZones[z.ID] = z
		i := p.item("domain", z.ID, z)
		a := accounts[z.AccountID]
		group := categories[z.CategoryID]
		if z.CategoryID != 0 {
			i.Category = group.Target
			i.categoryName = group.details.(Related).CategoryName
		}
		i.AccountID = a.AccountID
		exists := false
		switch {
		case group.Action == "conflict":
			i.conflict("category mapping conflicted")
		case a.Action == "conflict":
			i.conflict("account mapping conflicted")
		case a.AccountID == "":
			i.Action = "stage"
			i.Reason = "provider is staged"
		default:
			zoneID, err := zoneIdentity(a.details.(Account).Provider, z)
			if err != nil {
				i.conflict(err.Error())
			} else {
				i.ProviderZone = zoneID
			}
			key := [2]string{i.AccountID, i.ProviderZone}
			if identities[key] {
				i.conflict("duplicate target zone within source")
			}
			identities[key] = true
			if i.Action != "conflict" {
				params := dbx.Params{"a": i.AccountID, "z": i.ProviderZone}
				var current struct {
					ID   string `db:"id"`
					Name string `db:"name"`
				}
				err := db.NewQuery("SELECT id,name FROM dnsZone WHERE accountRef={:a} AND providerZoneId={:z}").Bind(params).WithContext(ctx).One(&current)
				if err == nil {
					exists = true
					i.Target = current.ID
					i.Action = "reuse"
					if !strings.EqualFold(strings.TrimSuffix(current.Name, "."), z.Name) {
						i.conflict("target zone name differs")
					}
				} else if errors.Is(err, sql.ErrNoRows) {
					_, collision, err := p.scalar("SELECT id FROM dnsZone WHERE id={:id}", dbx.Params{"id": i.Target})
					if err != nil {
						return nil, err
					}
					i.Action = "create"
					if collision {
						i.conflict("zone ID collision")
					}
				} else {
					return nil, err
				}
			}
		}
		if err := p.finish(&i, exists); err != nil {
			return nil, err
		}
		zones[z.ID] = i
	}
	for _, t := range m.Tasks {
		i := p.item(t.Kind, t.ID, t)
		z := zones[t.ZoneID]
		i.AccountID = z.AccountID
		i.ProviderZone = z.ProviderZone
		exists := false
		switch {
		case z.Action == "conflict":
			i.conflict("zone mapping conflicted")
		case i.AccountID == "":
			i.Action = "stage"
			i.Reason = "provider is staged"
		default:
			if t.Kind != "optimizeip" && !hasStableRecordID(accounts[sourceZones[t.ZoneID].AccountID].details.(Account).Provider) {
				i.Reason = "select the native record identity after zone synchronization"
			} else {
				i.definition, i.Reason = draft(t, sourceZones[t.ZoneID], i.AccountID, i.ProviderZone, m.Timezone)
			}
			if i.definition == nil {
				i.Action = "stage"
			} else {
				_, ok, err := p.scalar("SELECT id FROM dns_automation_tasks WHERE id={:id}", dbx.Params{"id": i.Target})
				if err != nil {
					return nil, err
				}
				exists = ok
				i.Action = "draft"
			}
		}
		if err := p.finish(&i, exists); err != nil {
			return nil, err
		}
		if exists && i.Action == "draft" {
			p.report.Items[len(p.report.Items)-1].conflict("task ID collision")
			p.report.Conflicts++
		}
	}
	for _, row := range m.Related {
		if row.Kind == "domain_category" {
			continue
		}
		i := p.item(row.Kind, row.ID, row)
		i.Action = "stage"
		for _, t := range relatedTables {
			if t.kind == row.Kind {
				i.Reason = t.reason
				break
			}
		}
		if err := p.finish(&i, false); err != nil {
			return nil, err
		}
	}
	if err := p.planPromotions(); err != nil {
		return nil, err
	}
	return &p.report, nil
}

func Apply(ctx context.Context, app core.App, m *Manifest, b Bindings) (*Report, error) {
	var report *Report
	err := app.RunInTransaction(func(tx core.App) error {
		var err error
		report, err = Plan(ctx, tx.DB(), m, b)
		if err != nil {
			return err
		}
		if report.Conflicts > 0 {
			return ErrConflict
		}
		for _, i := range report.Items {
			switch i.Action {
			case "unchanged":
				continue
			case "link":
				if _, err := dnscatalog.EnsureAccount(tx, i.AccountID); err != nil {
					return err
				}
			case "createCategory":
				z := i.details.(Related)
				c, err := tx.FindCollectionByNameOrId("dnsCategory")
				if err != nil {
					return err
				}
				r := core.NewRecord(c)
				r.Id = i.Target
				r.Set("name", z.CategoryName)
				r.Set("sort", z.State)
				if err := tx.SaveWithContext(ctx, r); err != nil {
					return err
				}
			case "create":
				z := i.details.(Zone)
				c, err := tx.FindCollectionByNameOrId("dnsZone")
				if err != nil {
					return err
				}
				r := core.NewRecord(c)
				r.Id = i.Target
				r.Set("accountRef", i.AccountID)
				r.Set("providerZoneId", i.ProviderZone)
				r.Set("name", z.Name)
				r.Set("status", "imported")
				r.Set("present", false)
				r.Set("expiresOn", z.Expires)
				r.Set("hidden", z.Hidden)
				r.Set("registeredOn", z.Registered)
				r.Set("categoryRef", i.Category)
				r.Set("groupName", i.categoryName)
				if err = tx.Save(r); err != nil {
					return err
				}
			case "draft":
				if _, err := dnsautomation.New(tx, nil, nil).CreateDraftWithID(ctx, i.Target, "dnsmgr-import", *i.definition); err != nil {
					return err
				}
			}
			data, err := json.Marshal(i.details)
			if err != nil {
				return err
			}
			if i.Action == "refreshStage" {
				result, err := tx.DB().NewQuery(`UPDATE dns_import_items SET details={:details},digest={:digest} WHERE source={:s} AND kind={:k} AND legacy_id={:id} AND disposition='stage'`).Bind(dbx.Params{"s": m.Source, "k": i.Kind, "id": i.Legacy, "details": string(data), "digest": i.digest}).WithContext(ctx).Execute()
				if err != nil {
					return err
				}
				affected, err := result.RowsAffected()
				if err != nil {
					return err
				}
				if affected != 1 {
					return ErrConflict
				}
				continue
			}
			_, err = tx.DB().NewQuery(`INSERT INTO dns_import_items(source,kind,legacy_id,target_id,digest,disposition,details) VALUES({:s},{:k},{:id},{:target},{:digest},{:disposition},{:details})`).Bind(dbx.Params{"s": m.Source, "k": i.Kind, "id": i.Legacy, "target": i.Target, "digest": i.digest, "disposition": i.Action, "details": string(data)}).WithContext(ctx).Execute()
			if err != nil {
				return err
			}
		}
		return report.applyPromotions(ctx, tx)
	})
	return report, err
}
