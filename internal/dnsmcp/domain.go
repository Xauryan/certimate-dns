package dnsmcp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	"golang.org/x/net/idna"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/dnscatalog"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

var domainTools = []toolDefinition{
	{"get_overview", "Summarize resources visible to this credential.", []operation{{"stat", "overview.read"}}, nil},
	{"list_provider_types", "Discover provider configuration schemas.", []operation{{"query", "provider.read"}}, []string{"category", "type"}},
	{"dns_account_query", "List authorized DNS account metadata.", []operation{{"list", "account.read"}}, []string{"kw", "offset", "limit"}},
	{"dns_account_manage", "Manage explicitly authorized DNS accounts.", []operation{{"add", "account.add"}, {"edit", "account.edit"}, {"del", "account.del"}}, []string{"id", "type", "name", "remark", "config"}},
	{"domain_manage", "Manage domains, local metadata and supported domain aliases.", []operation{{"add", "domain.add"}, {"batch_add", "domain.batch_add"}, {"edit", "domain.edit"}, {"del", "domain.del"}, {"batch_del", "domain.batch_del"}, {"batch_remark", "domain.batch_remark"}, {"batch_set_notice", "domain.batch_set_notice"}, {"refresh_expire", "domain.refresh_expire"}, {"update_date", "domain.update_date"}, {"set_category", "domain.set_category"}, {"alias_add", "domain.alias_add"}, {"alias_delete", "domain.alias_delete"}}, []string{"id", "ids", "aid", "name", "thirdid", "method", "recordcount", "domains", "is_hide", "is_sso", "is_notice", "cid", "expiretime", "remark", "alias", "alias_id"}},
	{"domain_category_manage", "Manage shared domain categories.", []operation{{"add", "category.add"}, {"edit", "category.edit"}, {"del", "category.del"}}, []string{"id", "name", "remark", "sort"}},
	{"operation_log_query", "Read scoped DNS operation history.", []operation{{"list", "operationlog.read"}}, []string{"uid", "domain", "kw", "offset", "limit"}},
}
var extendedDomainOps = []operation{{"aliases", "domain.read"}, {"remote_list", "inventory.read"}, {"categories", "category.read"}}

func (s service) executeDomain(e *core.RequestEvent, tool, action string, args object, grant scope) (object, *opError) {
	switch tool {
	case "dns_account_query", "dns_account_manage", "list_provider_types":
		return s.domainAccount(e, tool, action, args, grant)
	case "get_overview", "operation_log_query":
		return s.domainReport(e, tool, args, grant)
	case "domain_category_manage":
		return domainCategory(e, action, args, grant)
	case "domain_query":
		switch action {
		case "categories":
			return domainCategory(e, action, args, grant)
		case "aliases":
			return s.domainAlias(e, action, args, grant)
		case "remote_list":
			return s.domainInventory(e, action, args, grant)
		}
	case "domain_manage":
		switch action {
		case "alias_add", "alias_delete":
			return s.domainAlias(e, action, args, grant)
		case "add", "batch_add":
			return s.domainInventory(e, action, args, grant)
		default:
			return domainChange(e, action, args, grant)
		}
	}
	return nil, invalid
}

func domainOperationResult(value any, err error) (object, *opError) {
	if err != nil {
		var problem *domain.Error
		if errors.As(err, &problem) {
			switch problem.Code {
			case 400:
				return nil, invalid
			case 403:
				return nil, denied
			case 404:
				return nil, missing
			case 409:
				return nil, &opError{409, "Conflicting catalog state"}
			case 422:
				return nil, unsupported
			}
		}
		if errors.Is(err, sql.ErrNoRows) {
			return nil, missing
		}
		return nil, upstream
	}
	result := object{"code": 0, "msg": "OK"}
	if value != nil {
		result["data"] = value
	}
	return result, nil
}

func domainZone(e *core.RequestEvent, grant scope, id string, write bool) (dnsauth.Zone, *opError) {
	if id == "" {
		return dnsauth.Zone{}, invalid
	}
	if !slices.Contains(grant.Zones, id) {
		return dnsauth.Zone{}, missing
	}
	z, err := dnsauth.GetZone(e, id, write)
	if err != nil {
		_, problem := domainOperationResult(nil, err)
		return dnsauth.Zone{}, problem
	}
	return z, nil
}

func domainIDs(input any) ([]string, bool) {
	values, ok := input.([]any)
	if !ok || len(values) == 0 || len(values) > 100 {
		return nil, false
	}
	ids := make([]string, 0, len(values))
	for _, v := range values {
		id := str(object{"id": v}, "id")
		if id == "" || slices.Contains(ids, id) {
			return nil, false
		}
		ids = append(ids, id)
	}
	return ids, true
}

func domainFlag(args object, k string) (bool, bool) {
	if v, ok := args[k].(bool); ok {
		return v, true
	}
	switch str(args, k) {
	case "0", "false":
		return false, true
	case "1", "true":
		return true, true
	}
	return false, false
}

type aliasProvider interface {
	DomainAliases(context.Context, string) ([]dns.DomainAlias, error)
	AddDomainAlias(context.Context, string, string) error
	DeleteDomainAlias(context.Context, string, string) error
}

func (s service) domainAlias(e *core.RequestEvent, action string, args object, grant scope) (object, *opError) {
	z, problem := domainZone(e, grant, str(args, "id"), action != "aliases")
	if problem != nil {
		return nil, problem
	}
	ctx := e.Request.Context()
	p, err := s.resolve(ctx, z.Provider, z.AccessID, false)
	if err != nil {
		return nil, upstream
	}
	a, ok := p.(aliasProvider)
	if !ok {
		return nil, unsupported
	}
	switch action {
	case "aliases":
		aliases, err := a.DomainAliases(ctx, z.ZoneID)
		if err != nil {
			return nil, upstream
		}
		rows := make([]object, 0, len(aliases))
		for _, alias := range aliases {
			rows = append(rows, object{"Id": alias.ID, "DomainAlias": alias.Name})
		}
		return domainOperationResult(rows, nil)
	case "alias_add":
		name, err := idna.Lookup.ToASCII(strings.ToLower(strings.TrimSuffix(str(args, "alias"), ".")))
		if err != nil || len(name) > 253 || !strings.Contains(name, ".") || strings.ContainsAny(name, "*@/:") || strings.EqualFold(name, z.Name) {
			return nil, invalid
		}
		for _, l := range strings.Split(name, ".") {
			if l == "" || len(l) > 63 {
				return nil, invalid
			}
		}
		if !activeGrant(e) {
			return nil, denied
		}
		return domainOperationResult(nil, a.AddDomainAlias(ctx, z.ZoneID, name))
	case "alias_delete":
		id := str(args, "alias_id")
		if id == "" {
			return nil, invalid
		}
		aliases, err := a.DomainAliases(ctx, z.ZoneID)
		if err != nil {
			return nil, upstream
		}
		if !slices.ContainsFunc(aliases, func(row dns.DomainAlias) bool { return row.ID == id }) {
			return nil, missing
		}
		if !activeGrant(e) {
			return nil, denied
		}
		if _, problem := domainZone(e, grant, z.ID, true); problem != nil {
			return nil, problem
		}
		return domainOperationResult(nil, a.DeleteDomainAlias(ctx, z.ZoneID, id))
	}
	return nil, invalid
}

func (s service) domainInventory(e *core.RequestEvent, action string, args object, grant scope) (object, *opError) {
	account := str(args, "aid")
	if account == "" {
		return nil, invalid
	}
	if !e.HasSuperuserAuth() || !slices.Contains(grant.Accounts, account) {
		return nil, denied
	}
	ctx := e.Request.Context()
	switch action {
	case "add":
		method, ok := number(args, "method", 0, 0, 1)
		if !ok || str(args, "name") == "" {
			return nil, invalid
		}
		if method == 1 {
			z, err := dnscatalog.CreateZone(ctx, e.App, account, str(args, "name"), s.resolve)
			return domainOperationResult(z, err)
		}
		id := str(args, "thirdid")
		if id == "" {
			return nil, invalid
		}
		n, err := dnscatalog.ImportZones(ctx, e.App, account, []string{id}, s.resolve)
		return domainOperationResult(n, err)
	case "batch_add":
		raw, ok := args["domains"].([]any)
		if !ok || len(raw) == 0 || len(raw) > 100 {
			return nil, invalid
		}
		ids := make([]string, 0, len(raw))
		for _, v := range raw {
			d, ok := v.(map[string]any)
			id := str(d, "id")
			if !ok || str(d, "name") == "" || id == "" || slices.Contains(ids, id) {
				return nil, invalid
			}
			ids = append(ids, id)
		}
		n, err := dnscatalog.ImportZones(ctx, e.App, account, ids, s.resolve)
		return domainOperationResult(n, err)
	case "remote_list":
		page, ok := number(args, "page", 1, 1, 10000000)
		size, okSize := number(args, "pagesize", 10, 1, 100)
		if !ok || !okSize {
			return nil, invalid
		}
		keyword := strings.ToLower(str(args, "kw"))
		total := 0
		rows := []object{}
		local := map[string]bool{}
		var ids []string
		if err := e.App.DB().NewQuery("SELECT providerZoneId FROM dnsZone WHERE accountRef={:id} AND present=1").Bind(dbx.Params{"id": account}).WithContext(ctx).Column(&ids); err != nil {
			return nil, upstream
		}
		for _, id := range ids {
			local[id] = true
		}
		seen := map[string]bool{}
		expected := -1
		for p := 1; ; p++ {
			batch, err := dnscatalog.Discover(ctx, e.App, account, p, s.resolve)
			if err != nil {
				return domainOperationResult(nil, err)
			}
			if batch == nil || batch.Info.Page != p || batch.Info.Total < 0 || expected >= 0 && expected != batch.Info.Total {
				return nil, upstream
			}
			expected = batch.Info.Total
			for _, z := range batch.Items {
				if z.ID == "" || seen[z.ID] {
					return nil, upstream
				}
				seen[z.ID] = true
				if strings.Contains(strings.ToLower(z.Name), keyword) {
					if total >= (page-1)*size && len(rows) < size {
						rows = append(rows, object{"DomainId": z.ID, "Domain": z.Name, "Status": z.Status, "disabled": local[z.ID]})
					}
					total++
				}
			}
			if len(seen) == expected {
				break
			}
			if len(batch.Items) == 0 || len(seen) > expected {
				return nil, upstream
			}
		}
		return domainOperationResult(object{"total": total, "list": rows}, nil)
	}
	return nil, invalid
}

func domainCategory(e *core.RequestEvent, action string, args object, grant scope) (object, *opError) {
	if !e.HasSuperuserAuth() || !grant.Global {
		return nil, denied
	}
	id := str(args, "id")
	switch action {
	case "categories":
		rows, err := dnscatalog.ListCategories(e.App)
		return domainOperationResult(rows, err)
	case "del":
		if id == "" {
			return nil, invalid
		}
		return domainOperationResult(nil, dnscatalog.DeleteCategory(e.App, id))
	case "add", "edit":
		if action == "edit" && id == "" || action == "add" && id != "" {
			return nil, invalid
		}
		var patch dnscatalog.CategoryPatch
		if v, ok := args["name"]; ok {
			s, ok := v.(string)
			if !ok {
				return nil, invalid
			}
			patch.Name = &s
		}
		if v, ok := args["remark"]; ok {
			s, ok := v.(string)
			if !ok {
				return nil, invalid
			}
			patch.Remark = &s
		}
		if _, ok := args["sort"]; ok {
			v, ok := number(args, "sort", 0, -1<<31, 1<<31-1)
			if !ok {
				return nil, invalid
			}
			patch.Sort = &v
		}
		row, err := dnscatalog.SaveCategory(e.App, id, patch)
		return domainOperationResult(row, err)
	}
	return nil, invalid
}

func domainChange(e *core.RequestEvent, action string, args object, grant scope) (object, *opError) {
	if !e.HasSuperuserAuth() && action != "update_date" {
		return nil, denied
	}
	ids, ok := domainIDs(args["ids"])
	switch action {
	case "del", "edit", "update_date":
		ids = []string{str(args, "id")}
		ok = ids[0] != ""
	}
	if !ok {
		return nil, invalid
	}
	for _, id := range ids {
		if _, problem := domainZone(e, grant, id, true); problem != nil {
			return nil, problem
		}
	}
	ctx := e.Request.Context()
	switch action {
	case "refresh_expire", "update_date":
		for i, id := range ids {
			if !activeGrant(e) {
				return partial(i, len(ids), "Interface credential revoked")
			}
			if _, problem := domainZone(e, grant, id, true); problem != nil {
				return partial(i, len(ids), problem.message)
			}
			z, err := dnscatalog.RefreshRegistration(ctx, e.App, id)
			if err != nil {
				if len(ids) == 1 {
					return domainOperationResult(nil, err)
				}
				return partial(i, len(ids), "Registration lookup failed")
			}
			if action == "update_date" {
				return domainOperationResult(object{"expiretime": z.ExpiresOn}, nil)
			}
		}
		return domainOperationResult(len(ids), nil)
	}
	var problem *opError
	err := e.App.RunInTransaction(func(tx core.App) error {
		if !activeGrantIn(e, tx) {
			problem = denied
			return errors.New("credential revoked")
		}
		scoped := &core.RequestEvent{App: tx, Auth: e.Auth, Event: router.Event{Request: e.Request}}
		for _, id := range ids {
			if _, p := domainZone(scoped, grant, id, true); p != nil {
				problem = p
				return errors.New("authorization changed")
			}
		}
		change := dnscatalog.BatchChange{IDs: ids}
		switch action {
		case "del", "batch_del":
			change.Action = "delete"
		case "batch_remark":
			change.Action = "notes"
			s, ok := args["remark"].(string)
			if !ok {
				return domain.ErrInvalidParams
			}
			change.Notes = s
		case "batch_set_notice":
			change.Action = "notice"
			v, ok := domainFlag(args, "is_notice")
			if !ok {
				return domain.ErrInvalidParams
			}
			change.Enabled = v
		case "set_category":
			if _, ok := args["cid"]; !ok {
				return domain.ErrInvalidParams
			}
			return dnscatalog.AssignCategory(tx, ids, domainCategoryID(args))
		case "edit":
			return domainEdit(tx, ids[0], args)
		default:
			return domain.ErrInvalidParams
		}
		return dnscatalog.ChangeDomains(ctx, tx, change)
	})
	if problem != nil {
		return nil, problem
	}
	return domainOperationResult(nil, err)
}
func domainCategoryID(args object) string {
	id := str(args, "cid")
	if id == "0" {
		return ""
	}
	return id
}

func domainEdit(tx core.App, id string, args object) error {
	z, err := dnscatalog.AdminLookup(tx, id)
	if err != nil {
		return err
	}
	m := dnscatalog.Metadata{Tags: z.Tags, GroupName: z.GroupName, Notes: z.Notes, ExpiresOn: z.ExpiresOn, ReminderEnabled: z.ReminderEnabled, ReminderDays: z.ReminderDays, NotificationID: z.NotificationID, AutoRefresh: z.AutoRefresh}
	if v, ok := args["remark"]; ok {
		var valid bool
		m.Notes, valid = v.(string)
		if !valid {
			return domain.ErrInvalidParams
		}
	}
	if v, ok := args["expiretime"]; ok {
		t, valid := v.(string)
		if !valid {
			return domain.ErrInvalidParams
		}
		if t != "" {
			if d, err := time.Parse(time.DateTime, t); err == nil {
				t = d.Format(time.DateOnly)
			}
		}
		m.ExpiresOn = t
	}
	if _, ok := args["is_notice"]; ok {
		v, ok := domainFlag(args, "is_notice")
		if !ok {
			return domain.ErrInvalidParams
		}
		m.ReminderEnabled = v
	}
	if err := dnscatalog.UpdateMetadata(tx, id, m); err != nil {
		return err
	}
	if _, ok := args["cid"]; ok {
		if err := dnscatalog.AssignCategory(tx, []string{id}, domainCategoryID(args)); err != nil {
			return err
		}
	}
	r, err := tx.FindRecordById("dnsZone", id)
	if err != nil {
		return err
	}
	for k, field := range map[string]string{"is_hide": "hidden", "is_sso": "quickLoginEnabled"} {
		if _, ok := args[k]; ok {
			v, ok := domainFlag(args, k)
			if !ok {
				return domain.ErrInvalidParams
			}
			if r.Collection().Fields.GetByName(field) == nil {
				return fmt.Errorf("domain policy field unavailable")
			}
			r.Set(field, v)
		}
	}
	return tx.Save(r)
}

// domainListRow enriches an already authorized zone. Hidden zones are omitted
// from member discovery; direct resource access still follows the live grant.
func domainListRow(e *core.RequestEvent, z dnsauth.Zone, args object) (object, bool, *opError) {
	return domainMetadataRow(e, z, args, true)
}

func domainDetailRow(e *core.RequestEvent, z dnsauth.Zone) (object, *opError) {
	row, _, problem := domainMetadataRow(e, z, nil, false)
	return row, problem
}

func domainMetadataRow(e *core.RequestEvent, z dnsauth.Zone, args object, list bool) (object, bool, *opError) {
	d, err := dnscatalog.Lookup(e.App, z.ID)
	if err != nil {
		_, problem := domainOperationResult(nil, err)
		return nil, false, problem
	}
	if list && !e.HasSuperuserAuth() && d.Hidden {
		return nil, false, nil
	}
	if id := str(args, "id"); id != "" {
		if id != z.ID {
			return nil, false, nil
		}
	} else if kw := strings.ToLower(str(args, "kw")); kw != "" && !strings.Contains(strings.ToLower(d.Name+" "+d.Notes), kw) {
		return nil, false, nil
	}
	if aid := str(args, "aid"); aid != "" && aid != z.AccessID {
		return nil, false, nil
	}
	typ := legacyAccountType(z.Provider)
	if t := str(args, "type"); t != "" && t != typ && t != z.Provider {
		return nil, false, nil
	}
	if cid := str(args, "cid"); cid != "" && domainCategoryID(args) != d.CategoryID {
		return nil, false, nil
	}
	status := str(args, "status")
	if status != "" {
		today := time.Now().UTC()
		switch status {
		case "1":
			if d.ExpiresOn <= today.Format(time.DateOnly) || d.ExpiresOn > today.AddDate(0, 0, 30).Format(time.DateOnly) {
				return nil, false, nil
			}
		case "2":
			if d.ExpiresOn == "" || d.ExpiresOn > today.Format(time.DateOnly) {
				return nil, false, nil
			}
		default:
			return nil, false, invalid
		}
	}
	data := zoneInfo(z)
	data["type"] = typ
	data["typename"] = typ
	data["category_name"] = d.GroupName
	data["cid"] = d.CategoryID
	data["remark"] = d.Notes
	data["regtime"] = d.RegisteredOn
	data["expiretime"] = d.ExpiresOn
	data["is_notice"] = flag(d.ReminderEnabled)
	data["is_hide"] = flag(d.Hidden)
	data["is_sso"] = flag(z.QuickLoginEnabled)
	return data, true, nil
}
