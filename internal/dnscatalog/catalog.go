// Package dnscatalog stores DNS zone identity and local administrative metadata.
// Authoritative DNS records remain at the provider.
package dnscatalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/types"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type Resolve func(ctx context.Context, provider, accessID string, zones bool) (dns.Provider, error)

type Account struct {
	Notes       string `db:"notes" json:"notes"`
	DomainCount int    `db:"domainCount" json:"domainCount"`
	ID          string `db:"id" json:"id"`
	Name        string `db:"name" json:"name"`
	Provider    string `db:"provider" json:"provider"`
	Enabled     bool   `db:"enabled" json:"enabled"`
}

// The registry supplies build-time provider identifiers. Quote SQL literals here
// so every list, detail, activation check and reminder uses the same catalog.
func providerFilter() string {
	ids := dns.SupportedProviders()
	quoted := make([]string, 0, len(ids))
	for _, id := range ids {
		quoted = append(quoted, "'"+strings.ReplaceAll(id, "'", "''")+"'")
	}
	return " AND a.provider IN (" + strings.Join(quoted, ",") + ")"
}

var accountQuery = `SELECT a.id, a.name, a.provider, COALESCE(d.notes,'') AS notes, (SELECT COUNT(*) FROM dnsZone z WHERE z.accountRef=a.id) AS domainCount, NOT coalesce(d.disabled,0) AS enabled
FROM access a LEFT JOIN dnsAccount d ON d.id=a.id AND d.accessRef=a.id
WHERE a.deleted='' AND a.reserve='' ` + providerFilter()

func account(app core.App, id string) (*Account, error) {
	var a Account
	err := app.DB().NewQuery(accountQuery + " AND a.id={:id}").Bind(dbx.Params{"id": id}).One(&a)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrRecordNotFound
	}
	return &a, err
}

// IsEnabled accepts existing DNS access records until an administrator disables
// DNS management on that account. Missing and soft-deleted records are unavailable.
func IsEnabled(app core.App, accessID string) (bool, error) {
	a, err := account(app, accessID)
	if errors.Is(err, domain.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return a.Enabled, nil
}

// EnsureAccount materializes the account relation. Callers performing writes
// use this with the transaction app, so identity and dependent zones commit together.
func EnsureAccount(app core.App, accessID string) (*core.Record, error) {
	if _, err := account(app, accessID); err != nil {
		return nil, err
	}
	r, err := app.FindRecordById("dnsAccount", accessID)
	if err == nil || !errors.Is(err, sql.ErrNoRows) {
		return r, err
	}
	c, err := app.FindCollectionByNameOrId("dnsAccount")
	if err != nil {
		return nil, err
	}
	r = core.NewRecord(c)
	r.Id = accessID
	r.Set("accessRef", accessID)
	return r, app.Save(r)
}

type Domain struct {
	Hidden              bool                    `db:"hidden" json:"hidden"`
	ID                  string                  `db:"id" json:"id"`
	AccessID            string                  `db:"accountRef" json:"accessId"`
	AccountName         string                  `db:"accountName" json:"accountName"`
	Provider            string                  `db:"provider" json:"provider"`
	ZoneID              string                  `db:"providerZoneId" json:"zoneId"`
	Name                string                  `db:"name" json:"name"`
	Status              string                  `db:"status" json:"status"`
	Present             bool                    `db:"present" json:"present"`
	Enabled             bool                    `db:"enabled" json:"enabled"`
	Tags                types.JSONArray[string] `db:"tags" json:"tags"`
	GroupName           string                  `db:"groupName" json:"groupName"`
	Notes               string                  `db:"notes" json:"notes"`
	RegisteredOn        string                  `db:"registeredOn" json:"registeredOn"`
	RegistrationStatus  string                  `db:"registrationStatus" json:"registrationStatus"`
	RegistrationChecked string                  `db:"registrationChecked" json:"registrationChecked"`
	AutoRefresh         bool                    `db:"autoRefresh" json:"autoRefresh"`
	CategoryID          string                  `db:"categoryRef" json:"categoryId"`
	ExpiresOn           string                  `db:"expiresOn" json:"expiresOn"`
	ReminderEnabled     bool                    `db:"reminderEnabled" json:"reminderEnabled"`
	ReminderDays        int                     `db:"reminderDays" json:"reminderDays"`
	NotificationID      string                  `db:"notificationRef" json:"notificationId"`
}

var fromZones = ` FROM dnsZone z JOIN dnsAccount d ON z.accountRef=d.id
JOIN access a ON a.id=d.accessRef AND a.id=d.id
WHERE a.deleted='' AND a.reserve='' ` + providerFilter()

const selectZone = `SELECT z.id,z.accountRef,a.name AS accountName,a.provider,z.providerZoneId,
z.name,z.status,z.present,NOT d.disabled AS enabled,z.tags,z.groupName,z.notes,z.expiresOn,
z.hidden,z.reminderEnabled,z.reminderDays,z.notificationRef,z.registeredOn,z.registrationStatus,z.registrationChecked,z.autoRefresh,z.categoryRef`

func lookup(app core.App, id, condition string) (*Domain, error) {
	var z Domain
	err := app.DB().NewQuery(selectZone + fromZones + " AND z.id={:id}" + condition).Bind(dbx.Params{"id": id}).One(&z)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrRecordNotFound
	}
	return &z, err
}

// AdminLookup includes disabled and absent zones for administrative editing.
func AdminLookup(app core.App, id string) (*Domain, error) { return lookup(app, id, "") }

// Lookup is for operations on a live DNS zone. Administrative views can still
// display history and notes for zones absent from the last successful sync.
func Lookup(app core.App, domainID string) (*Domain, error) {
	return lookup(app, domainID, " AND d.disabled=0 AND z.present=1")
}

// LookupZone validates all provider-side identity components. ProviderZoneIDs
// such as domain names and numeric IDs can be reused across different accounts.
func LookupZone(app core.App, provider, accountID, providerZoneID string) (*Domain, error) {
	var z Domain
	err := app.DB().NewQuery(selectZone + fromZones +
		" AND d.disabled=0 AND z.present=1 AND a.provider={:provider} AND z.accountRef={:account} AND z.providerZoneId={:zone}").
		Bind(dbx.Params{"provider": provider, "account": accountID, "zone": providerZoneID}).One(&z)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrRecordNotFound
	}
	return &z, err
}

type Metadata struct {
	Hidden          *bool    `json:"hidden"`
	AutoRefresh     bool     `json:"autoRefresh"`
	Tags            []string `json:"tags"`
	GroupName       string   `json:"groupName"`
	Notes           string   `json:"notes"`
	ExpiresOn       string   `json:"expiresOn"`
	ReminderEnabled bool     `json:"reminderEnabled"`
	ReminderDays    int      `json:"reminderDays"`
	NotificationID  string   `json:"notificationId"`
}

func UpdateMetadata(app core.App, id string, m Metadata) error {
	m.GroupName = strings.TrimSpace(m.GroupName)
	if utf8.RuneCountInString(m.GroupName) > 128 || utf8.RuneCountInString(m.Notes) > 2048 || len(m.Tags) > 32 || m.ReminderDays < 0 || m.ReminderDays > 365 || (m.ReminderEnabled && m.ExpiresOn == "" && !m.AutoRefresh) {
		return domain.ErrInvalidParams
	}
	if m.ExpiresOn != "" {
		if _, err := time.Parse(time.DateOnly, m.ExpiresOn); err != nil {
			return domain.ErrInvalidParams
		}
	}
	tags := make([]string, 0, len(m.Tags))
	seen := map[string]bool{}
	for _, v := range m.Tags {
		v = strings.TrimSpace(v)
		if v == "" || utf8.RuneCountInString(v) > 64 {
			return domain.ErrInvalidParams
		}
		if !seen[v] {
			tags = append(tags, v)
			seen[v] = true
		}
	}
	return app.RunInTransaction(func(tx core.App) error {
		if _, err := lookup(tx, id, ""); err != nil {
			return err
		}
		if m.NotificationID != "" {
			var count int
			err := tx.DB().NewQuery("SELECT count(*) FROM access WHERE id={:id} AND deleted='' AND reserve='notif'").Bind(dbx.Params{"id": m.NotificationID}).Row(&count)
			if err != nil {
				return err
			}
			if count != 1 {
				return domain.ErrInvalidParams
			}
		}
		r, err := tx.FindRecordById("dnsZone", id)
		if err != nil {
			return err
		}
		r.Set("tags", tags)
		if err := setZoneGroupName(tx, r, m.GroupName); err != nil {
			return err
		}
		r.Set("autoRefresh", m.AutoRefresh)
		if m.Hidden != nil {
			r.Set("hidden", *m.Hidden)
		}
		r.Set("notes", m.Notes)
		r.Set("expiresOn", m.ExpiresOn)
		r.Set("reminderEnabled", m.ReminderEnabled)
		r.Set("reminderDays", m.ReminderDays)
		r.Set("notificationRef", m.NotificationID)
		return tx.Save(r)
	})
}

type Filter struct {
	AccountID, Search, GroupName, Tag string
	Due                               bool
	Page                              int
}
type Page struct {
	Items []Domain `json:"items"`
	Total int      `json:"total"`
}

const pageSize = 25

// CountDomains counts the entries visible in the unfiltered admin catalog.
func CountDomains(ctx context.Context, app core.App) (int, error) {
	var total int
	err := app.DB().NewQuery("SELECT count(*)" + fromZones).WithContext(ctx).Row(&total)
	return total, err
}

// Due dates are calendar days in UTC. An overdue domain remains in the
// reminders view until its expiry date is corrected or reminders are disabled.
const dueClause = ` AND z.present=1 AND d.disabled=0 AND z.reminderEnabled=1 AND z.expiresOn<>''
AND date(z.expiresOn) <= date({:today}, '+' || cast(z.reminderDays AS integer) || ' days')`

func listDomains(ctx context.Context, app core.App, f Filter, now time.Time) (Page, error) {
	result := Page{Items: []Domain{}}
	if f.Page <= 0 || f.Page > 10000000 {
		return result, domain.ErrInvalidParams
	}
	where := fromZones
	p := dbx.Params{}
	for _, filter := range []struct{ v, k, sql string }{
		{f.AccountID, "account", " AND z.accountRef={:account}"}, {f.Search, "search", " AND (instr(lower(z.name),lower({:search}))>0 OR instr(lower(z.notes),lower({:search}))>0)"},
		{f.GroupName, "groupName", " AND z.groupName={:groupName}"}, {f.Tag, "tag", " AND EXISTS(SELECT 1 FROM json_each(z.tags) WHERE value={:tag})"},
	} {
		if filter.v != "" {
			where += filter.sql
			p[filter.k] = filter.v
		}
	}
	if f.Due {
		where += dueClause
		p["today"] = now.UTC().Format(time.DateOnly)
	}
	err := app.DB().NewQuery("SELECT count(*)" + where).Bind(p).WithContext(ctx).Row(&result.Total)
	if err != nil {
		return result, err
	}
	order := " ORDER BY z.name,z.id"
	if f.Due {
		order = " ORDER BY z.expiresOn,z.id"
	}
	err = app.DB().NewQuery(selectZone + where + order + fmt.Sprintf(" LIMIT %d OFFSET %d", pageSize, (f.Page-1)*pageSize)).Bind(p).WithContext(ctx).All(&result.Items)
	return result, err
}
