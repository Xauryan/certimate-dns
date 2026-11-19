package dnsmcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnscatalog"
	"github.com/certimate-go/certimate/internal/dnsmanagement"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

var (
	errGrantWithdrawn   = errors.New("DNS interface grant withdrawn")
	accountStorageError = &opError{500, "Could not access DNS accounts"}
	accountConflict     = &opError{409, "Account changed, has associated zones, or name is already in use"}
	errAccountConflict  = errors.New("DNS account conflict")
	errAccountMissing   = errors.New("DNS account unavailable")
)

func (s service) domainAccount(e *core.RequestEvent, tool, action string, args object, grant scope) (object, *opError) {
	switch tool {
	case "list_provider_types":
		return interfaceProviderTypes(args)
	case "dns_account_query":
		return interfaceAccountList(e, args, grant)
	case "dns_account_manage":
		id := str(args, "id")
		if !e.HasSuperuserAuth() || (action == "add" && !grant.Global) || (action != "add" && !slices.Contains(grant.Accounts, id)) {
			return nil, denied
		}
		if action == "del" {
			return removeInterfaceAccount(e, id)
		}
		if action != "add" && action != "edit" {
			return nil, invalid
		}
		check := func(ctx context.Context, account *domain.Access) *opError {
			p, err := dnsmanagement.Open(account, true, e.App)
			if err != nil {
				return invalid
			}
			probe, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			first, err := p.Zones(probe, 1)
			if err != nil || first == nil || first.Info.Page != 1 || first.Info.Total < 0 {
				return upstream
			}
			return nil
		}
		return saveInterfaceAccount(e, action, args, check)
	default:
		return nil, invalid
	}
}

type interfaceAccountRow struct {
	ID      string `db:"id" json:"id"`
	Type    string `db:"provider" json:"type"`
	Name    string `db:"name" json:"name"`
	Remark  string `db:"remark" json:"remark"`
	Enabled bool   `db:"enabled" json:"enabled"`
}

func interfaceAccountList(e *core.RequestEvent, args object, grant scope) (object, *opError) {
	offset, limit, ok := paging(args)
	if !ok {
		return nil, invalid
	}
	ids := grant.Accounts
	if !e.HasSuperuserAuth() {
		ids = nil
	}
	reachable, _ := json.Marshal(ids)
	providers, _ := json.Marshal(dns.SupportedProviders())
	// Restrict by account, state and provider in the query shared by count and page.
	from := ` FROM access a LEFT JOIN dnsAccount d ON d.accessRef=a.id AND d.id=a.id
			WHERE a.deleted='' AND a.reserve='' AND a.provider IN (SELECT value FROM json_each({:providers}))`
	from += " AND coalesce(d.disabled,0)=0 AND a.id IN (SELECT value FROM json_each({:reachable}))"
	from += " AND (instr(lower(a.name),lower({:kw}))>0 OR instr(lower(coalesce(d.notes,'')),lower({:kw}))>0)"
	parameters := dbx.Params{"providers": string(providers), "kw": str(args, "kw"), "reachable": string(reachable), "limit": limit, "offset": offset}
	var total int
	rows := []interfaceAccountRow{}
	ctx := e.Request.Context()
	err := e.App.RunInTransaction(func(tx core.App) error {
		if err := tx.DB().NewQuery("SELECT count(*)" + from).Bind(parameters).WithContext(ctx).Row(&total); err != nil {
			return err
		}
		return tx.DB().NewQuery("SELECT a.id,a.name,a.provider,coalesce(d.notes,'') AS remark,NOT coalesce(d.disabled,0) AS enabled" + from + " ORDER BY a.name,a.id LIMIT {:limit} OFFSET {:offset}").Bind(parameters).WithContext(ctx).All(&rows)
	})
	if err != nil {
		return nil, accountStorageError
	}
	for i := range rows {
		rows[i].Type = legacyAccountType(rows[i].Type)
	}
	return object{"total": total, "rows": rows}, nil
}

func currentInterfaceAccount(app core.App, id string) (*core.Record, error) {
	r, err := app.FindRecordById(domain.CollectionNameAccess, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errAccountMissing
	}
	if err != nil {
		return nil, err
	}
	if r.GetString("deleted") != "" || r.GetString("reserve") != "" || !dns.IsSupportedProvider(r.GetString("provider")) {
		return nil, errAccountMissing
	}
	enabled, err := dnscatalog.IsEnabled(app, id)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, errAccountMissing
	}
	return r, nil
}

func delegatedAccountProbeAllowed(provider string, config object) bool {
	switch provider {
	case "aws":
		method, ok := config["authMethod"]
		return !ok || method == "" || method == "accesskey"
	case "aliyun", "tencentcloud", "huaweicloud", "baiducloud", "westcn", "volcengine",
		"jdcloud", "dnsla", "qingcloud", "bt", "cloudflare", "namesilo", "henet", "spaceship",
		"aliyunesa", "tencenteo", "dynv6":
		return true
	default:
		return false
	}
}

func accountFailure(err error) *opError {
	switch {
	case errors.Is(err, errGrantWithdrawn):
		return denied
	case errors.Is(err, errAccountMissing):
		return missing
	case errors.Is(err, errAccountConflict):
		return accountConflict
	default:
		return accountStorageError
	}
}

func accountNote(app core.App, id string) (string, error) {
	var note string
	err := app.DB().NewQuery("SELECT coalesce(max(notes),'') FROM dnsAccount WHERE id={:id} AND accessRef={:id}").Bind(dbx.Params{"id": id}).Row(&note)
	return note, err
}

type checkAccount func(context.Context, *domain.Access) *opError

func saveInterfaceAccount(e *core.RequestEvent, action string, args object, check checkAccount) (object, *opError) {
	id := str(args, "id")
	t := str(args, "type")
	notes := ""
	original := object{}
	var oldRecord *core.Record
	var err error
	if action == "edit" {
		if id == "" {
			return nil, invalid
		}
		oldRecord, err = currentInterfaceAccount(e.App, id)
		if err != nil {
			return nil, accountFailure(err)
		}
		if err := oldRecord.UnmarshalJSONField("config", &original); err != nil {
			return nil, accountStorageError
		}
		native := oldRecord.GetString("provider")
		if t != "" && nativeAccountType(t) != native {
			return nil, unsupported
		}
		t = legacyAccountType(native)
		notes, err = accountNote(e.App, id)
		if err != nil {
			return nil, accountStorageError
		}
	} else if id != "" {
		return nil, invalid
	}
	t = legacyAccountType(nativeAccountType(t))
	def, ok := accountDefinitions[t]
	if !ok || !dns.IsSupportedProvider(def.native) {
		return nil, unsupported
	}
	name := def.label
	if oldRecord != nil {
		name = oldRecord.GetString("name")
	}
	if value, found := args["name"]; found {
		s, ok := value.(string)
		if !ok {
			return nil, invalid
		}
		name = strings.TrimSpace(s)
	}
	if name == "" || utf8.RuneCountInString(name) > 128 {
		return nil, invalid
	}
	newNotes := notes
	if value, found := args["remark"]; found {
		s, ok := value.(string)
		if !ok || utf8.RuneCountInString(s) > 2048 {
			return nil, invalid
		}
		newNotes = s
	}
	patch, ok := args["config"].(object)
	if !ok && (args["config"] != nil || action == "add") {
		return nil, invalid
	}
	config, problem := mergeAccountConfig(t, original, patch)
	if problem != nil {
		return nil, problem
	}
	// External keys may validate accounts only against fixed provider APIs.
	// Self-hosted endpoints belong to the operator configuration flow. Never
	// resolve or dial an externally supplied address, including on an edit.
	if !delegatedAccountProbeAllowed(def.native, config) {
		return nil, denied
	}
	proposed := domain.Access{Name: name, Provider: def.native, Config: config}
	if problem := check(e.Request.Context(), &proposed); problem != nil {
		return nil, problem
	}

	// Check the candidate outside the write transaction. Compare against the
	// exact credential and catalog values read before the network round-trip.
	err = e.App.RunInTransaction(func(tx core.App) error {
		if !activeGrantIn(e, tx) {
			return errGrantWithdrawn
		}
		var r *core.Record
		if oldRecord == nil {
			c, err := tx.FindCollectionByNameOrId(domain.CollectionNameAccess)
			if err != nil {
				return err
			}
			r = core.NewRecord(c)
		} else {
			var err error
			r, err = currentInterfaceAccount(tx, id)
			if err != nil {
				return err
			}
			var now object
			if err := r.UnmarshalJSONField("config", &now); err != nil {
				return err
			}
			currentNote, err := accountNote(tx, id)
			if err != nil {
				return err
			}
			if r.GetString("name") != oldRecord.GetString("name") || r.GetString("provider") != def.native || !reflect.DeepEqual(now, original) || currentNote != notes {
				return errAccountConflict
			}
		}
		var duplicate bool
		err := tx.DB().NewQuery("SELECT EXISTS(SELECT 1 FROM access WHERE id!={:id} AND provider={:p} AND name={:n} AND reserve='' AND deleted='')").Bind(dbx.Params{"id": id, "p": def.native, "n": name}).Row(&duplicate)
		if err != nil {
			return err
		}
		if duplicate {
			return errAccountConflict
		}
		r.Set("provider", def.native)
		r.Set("name", name)
		r.Set("config", config)
		if err := tx.SaveWithContext(e.Request.Context(), r); err != nil {
			return err
		}
		meta, err := dnscatalog.EnsureAccount(tx, r.Id)
		if err != nil {
			return err
		}
		meta.Set("notes", newNotes)
		id = r.Id
		return tx.SaveWithContext(e.Request.Context(), meta)
	})
	if err != nil {
		return nil, accountFailure(err)
	}
	return object{"code": 0, "id": id}, nil
}

func removeInterfaceAccount(e *core.RequestEvent, id string) (object, *opError) {
	if id == "" {
		return nil, invalid
	}
	err := e.App.RunInTransaction(func(tx core.App) error {
		if !activeGrantIn(e, tx) {
			return errGrantWithdrawn
		}
		r, err := currentInterfaceAccount(tx, id)
		if err != nil {
			return err
		}
		var referenced bool
		err = tx.DB().NewQuery("SELECT EXISTS(SELECT 1 FROM dnsZone WHERE accountRef={:id})").Bind(dbx.Params{"id": id}).Row(&referenced)
		if err != nil {
			return err
		}
		if referenced {
			return errAccountConflict
		}
		// Match the Certimate access lifecycle. Existing workflows can still
		// display their original reference and the application rejects its use.
		r.Set("deleted", time.Now().UTC())
		return tx.SaveWithContext(e.Request.Context(), r)
	})
	if err != nil {
		return nil, accountFailure(err)
	}
	return object{"code": 0}, nil
}
