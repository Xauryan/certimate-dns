package dnsmcp

import (
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

var certAccountTools = []toolDefinition{
	{"cert_account_query", "List authorized certificate issuer or deployment accounts. Credentials are omitted.", []operation{{"list", "cert.account.read"}}, []string{"deploy", "kw", "offset", "limit"}},
	{"cert_account_manage", "Add and maintain native issuer or deployment credentials. Set deploy=1 for deployment accounts.", []operation{{"add", "cert.account.add"}, {"edit", "cert.account.edit"}, {"del", "cert.account.delete"}}, []string{"deploy", "type", "id", "name", "remark", "config"}},
}

type certAccountRow struct {
	ID       string `db:"id" json:"id"`
	Name     string `db:"name" json:"name"`
	Type     string `db:"legacy_type" json:"type"`
	Provider string `db:"provider" json:"nativeProvider"`
	Remark   string `db:"remark" json:"remark"`
	Created  string `db:"created" json:"addtime"`
	Deploy   int    `db:"deploy" json:"deploy"`
	Reserve  string `db:"reserve" json:"-"`
}

func accountText(args object, k string, max int) (string, bool) {
	s, ok := args[k].(string)
	return strings.TrimSpace(s), ok && len(s) <= max && strings.IndexFunc(s, unicode.IsControl) < 0
}

// Native, unclassified credentials may be shared with workflows and DNS accounts.
// Only show unambiguous eligible credentials and only mutate credentials explicitly
// created for the corresponding certificate account role.
func certAccountRows(e *core.RequestEvent, grant scope, deploy int, args object) (object, *opError) {
	offset, limit, ok := paging(args)
	if !ok {
		return nil, invalid
	}
	query := `SELECT a.id,a.name,a.provider,a.reserve,a.created,COALESCE(m.legacy_type,'') AS legacy_type,
		COALESCE(m.remark,'') AS remark,COALESCE(m.deploy,-1) AS deploy FROM access a
		LEFT JOIN dns_cert_account_meta m ON m.access_id=a.id WHERE a.deleted='' AND a.id IN (SELECT value FROM json_each({:ids})) ORDER BY a.id DESC`
	ids, _ := json.Marshal(grant.Accounts)
	rows := []certAccountRow{}
	if err := e.App.DB().NewQuery(query).Bind(dbx.Params{"ids": string(ids)}).WithContext(e.Request.Context()).All(&rows); err != nil {
		return nil, accountDBError
	}
	out := []certAccountRow{}
	keyword := strings.ToLower(str(args, "kw"))
	specs := certAccountSpecs(deploy == 1)
	for _, row := range rows {
		if row.Deploy >= 0 {
			spec, known := specs[row.Type]
			if row.Deploy != deploy || !known || !spec.matchesNative(row.Provider) {
				continue
			}
		} else {
			if row.Reserve == "notif" || deploy == 1 && row.Reserve == "ca" {
				continue
			}
			row.Type = ""
			for _, key := range certSortedTypes(specs) {
				if specs[key].matchesNative(row.Provider) && (deploy == 1 || row.Reserve == "ca" || !specs[key].acme()) {
					row.Type = key
					break
				}
			}
			if row.Type == "" {
				continue
			}
			row.Deploy = deploy
		}
		if keyword != "" && row.ID != keyword && !strings.Contains(strings.ToLower(row.Name), keyword) && !strings.Contains(strings.ToLower(row.Remark), keyword) {
			continue
		}
		out = append(out, row)
	}
	return page(out, offset, limit), nil
}

func certSortedTypes(specs map[string]certAccountSpec) []string {
	keys := make([]string, 0, len(specs))
	for k := range specs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var accountDBError = &opError{500, "Certificate account storage operation failed"}
var accountInUse = &opError{409, "The credential is in use"}
var accountChangeConflict = &opError{409, "Credential changed; reload before editing"}

// Use the request's PocketBase app throughout the transaction. No access config
// or database error text can enter the MCP response or the application log.
func (s service) certAccounts(e *core.RequestEvent, tool, action string, args object, grant scope) (object, *opError) {
	if !e.HasSuperuserAuth() {
		return nil, denied
	}
	deploy, ok := number(args, "deploy", 0, 0, 1)
	if !ok {
		return nil, invalid
	}
	if tool == "cert_account_query" && action == "list" {
		return certAccountRows(e, grant, deploy, args)
	}
	if tool != "cert_account_manage" || !grant.Global || !slices.Contains([]string{"add", "edit", "del"}, action) {
		return nil, denied
	}
	id := str(args, "id")
	if action != "add" && !slices.Contains(grant.Accounts, id) {
		return nil, denied
	}
	if action == "add" && id != "" {
		return nil, invalid
	}
	var problem *opError
	err := e.App.RunInTransaction(func(tx core.App) error {
		result, err := certAccountChange(tx, id, action, deploy, args)
		if err != nil {
			problem = err
			return errors.New("certificate account operation failed")
		}
		id = result
		return nil
	})
	if err != nil {
		if problem == nil {
			problem = accountDBError
		}
		return nil, problem
	}
	e.App.Logger().Info("Certificate interface account change", "actor", e.Auth.Id, "operation", action, "account", id)
	return object{"code": 0, "id": id}, nil
}

func certAccountChange(app core.App, id, action string, deploy int, args object) (string, *opError) {
	kind := str(args, "type")
	var rec *core.Record
	var err error
	var remark string
	if action == "add" {
		c, err := app.FindCollectionByNameOrId("access")
		if err != nil {
			return "", accountDBError
		}
		rec = core.NewRecord(c)
	} else {
		var meta struct {
			Type   string `db:"legacy_type"`
			Remark string `db:"remark"`
		}
		err = app.DB().NewQuery("SELECT legacy_type,remark FROM dns_cert_account_meta WHERE access_id={:id} AND deploy={:deploy}").Bind(dbx.Params{"id": id, "deploy": deploy}).One(&meta)
		if errors.Is(err, sql.ErrNoRows) {
			return "", missing
		}
		if err != nil {
			return "", accountDBError
		}
		if kind != "" && kind != meta.Type {
			return "", invalid
		}
		kind, remark = meta.Type, meta.Remark
		rec, err = app.FindRecordById("access", id)
		if errors.Is(err, sql.ErrNoRows) {
			return "", missing
		}
		if err != nil {
			return "", accountDBError
		}
		if rec.GetString("deleted") != "" {
			return "", missing
		}
	}
	spec, ok := certAccountSpecs(deploy == 1)[kind]
	if !ok {
		return "", unsupported
	}
	if action != "add" && (!spec.matchesNative(rec.GetString("provider")) || rec.GetString("reserve") != spec.reserve()) {
		return "", accountChangeConflict
	}
	if action == "del" {
		var used bool
		// Workflows store credential IDs in JSON graphs, including unpublished drafts.
		err := app.DB().NewQuery(`SELECT EXISTS(SELECT 1 FROM dns_cert_orders WHERE access_id={:id})
			OR EXISTS(SELECT 1 FROM dns_cert_deploy WHERE access_id={:id})
			OR EXISTS(SELECT 1 FROM dnsAccount WHERE accessRef={:id})
			OR EXISTS(SELECT 1 FROM workflow w WHERE
				EXISTS(SELECT 1 FROM json_tree(w.graphContent) j WHERE j.type='text' AND j.value={:id})
				OR EXISTS(SELECT 1 FROM json_tree(w.graphDraft) j WHERE j.type='text' AND j.value={:id}))`).Bind(dbx.Params{"id": id}).Row(&used)
		if err != nil {
			return "", accountDBError
		}
		if used {
			return "", accountInUse
		}
		rec.Set("deleted", time.Now().UTC())
		if err := app.Save(rec); err != nil {
			return "", accountDBError
		}
		return id, nil
	}
	if _, provided := args["remark"]; provided {
		v, ok := accountText(args, "remark", 255)
		if !ok {
			return "", invalid
		}
		remark = v
	}
	if _, provided := args["name"]; provided {
		v, ok := accountText(args, "name", 128)
		if !ok || v == "" {
			return "", invalid
		}
		rec.Set("name", v)
	} else if action == "add" {
		rec.Set("name", kind)
	}
	cfg := object{}
	if action != "add" && rec.UnmarshalJSONField("config", &cfg) != nil {
		return "", accountDBError
	}
	if cfg == nil {
		cfg = object{}
	}
	if _, provided := args["config"]; provided || action == "add" {
		patch, ok := args["config"].(map[string]any)
		if !ok || patch == nil {
			return "", invalid
		}
		native, problem := spec.configure(cfg, patch)
		if problem != nil {
			return "", problem
		}
		if action != "add" && native != rec.GetString("provider") {
			return "", accountChangeConflict
		}
		rec.Set("provider", native)
		rec.Set("reserve", spec.reserve())
		rec.Set("config", cfg)
	}
	if err := app.Save(rec); err != nil {
		return "", accountDBError
	}
	_, err = app.DB().NewQuery(`INSERT INTO dns_cert_account_meta(access_id,legacy_type,deploy,remark) VALUES({:id},{:kind},{:deploy},{:remark}) ON CONFLICT(access_id) DO UPDATE SET remark=excluded.remark`).Bind(dbx.Params{"id": rec.Id, "kind": kind, "deploy": deploy, "remark": remark}).Execute()
	if err != nil {
		return "", accountDBError
	}
	return rec.Id, nil
}
