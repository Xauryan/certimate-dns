// Package dnsmcp exposes DNSMgr-compatible external DNS endpoints.
package dnsmcp

import (
	"crypto/hmac"
	"crypto/md5" // DNSMgr's existing signed-form protocol.
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/hook"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/dnssign"
)

type scope struct {
	Interfaces []string `json:"interfaces"`
	Actions    []string `json:"actions"`
	Zones      []string `json:"zones"`
	Accounts   []string `json:"accounts,omitempty"`
	Global     bool     `json:"global,omitempty"`
}

type keyInput struct {
	Label string `json:"label"`
	scope
}

type keyRow struct {
	UID        string `db:"uid"`
	Collection string `db:"owner_collection"`
	Owner      string `db:"owner"`
	Label      string `db:"label"`
	Scope      string `db:"scope"`
}

const scopeKey = "dns.interface.key.scope"

func actorAllowed(r *core.Record) bool {
	return r != nil && (r.IsSuperuser() || (r.Collection().Name == dnsauth.Members && !r.GetBool("disabled")))
}

func apiEnabled(r *core.Record) bool {
	return actorAllowed(r) && (r.IsSuperuser() || r.GetBool("apiEnabled"))
}

func uniqueAllowed(values, allowed []string) bool {
	if len(values) == 0 || len(values) > len(allowed) {
		return false
	}
	for i, v := range values {
		if !slices.Contains(allowed, v) || slices.Contains(values[:i], v) {
			return false
		}
	}
	return true
}

// Derive a separate key for each interface credential. Rotating the PB owner's token key
// invalidates all issued credentials. No retrievable interface secret is stored.
func secretFor(uid string, owner *core.Record) string {
	mac := hmac.New(sha256.New, []byte(owner.TokenKey()))
	mac.Write([]byte("certimate/dns/interface-key/v1/" + owner.Collection().Id + "/" + owner.Id + "/" + uid))
	return hex.EncodeToString(mac.Sum(nil))
}

func issueKey(e *core.RequestEvent) error {
	if !apiEnabled(e.Auth) || e.Auth.TokenKey() == "" {
		return e.ForbiddenError("Inactive owner", nil)
	}
	var in keyInput
	if e.BindBody(&in) != nil || strings.TrimSpace(in.Label) == "" || len(in.Label) > 100 ||
		!uniqueAllowed(in.Interfaces, []string{"api", "mcp"}) || !uniqueAllowed(in.Actions, actionsForActor(e.Auth)) ||
		(len(in.Zones) == 0 && len(in.Accounts) == 0 && !in.Global) || len(in.Zones) > 100 || len(in.Accounts) > 100 {
		return e.BadRequestError("Invalid label, interfaces, actions or zones", nil)
	}
	if (in.Global || len(in.Accounts) != 0) && !e.HasSuperuserAuth() {
		return e.ForbiddenError("Administrator scope required", nil)
	}
	for i, id := range in.Accounts {
		if id == "" || slices.Contains(in.Accounts[:i], id) {
			return e.BadRequestError("Invalid account IDs", nil)
		}
		var exists bool
		err := e.App.DB().NewQuery("SELECT EXISTS(SELECT 1 FROM access WHERE id={:id} AND deleted='')").Bind(dbx.Params{"id": id}).WithContext(e.Request.Context()).Row(&exists)
		if err != nil || !exists {
			return e.BadRequestError("Unknown account", nil)
		}
	}
	write := slices.ContainsFunc(in.Actions, isZoneWrite)
	for i, z := range in.Zones {
		if z == "" || slices.Contains(in.Zones[:i], z) {
			return e.BadRequestError("Invalid domain IDs", nil)
		}
		if _, err := dnsauth.GetZone(e, z, write); err != nil {
			return e.ForbiddenError("Insufficient domain grant", nil)
		}
	}
	// Keep numeric UIDs representable without loss in JavaScript DNSMgr clients.
	n, err := rand.Int(rand.Reader, big.NewInt(1<<52))
	if err != nil {
		return e.InternalServerError("Could not issue credential", nil)
	}
	uid := strconv.FormatInt(n.Int64()+1, 10)
	encoded, err := json.Marshal(in.scope)
	if err != nil {
		return err
	}
	_, err = e.App.DB().NewQuery(`INSERT INTO dns_interface_keys (uid,owner_collection,owner,label,scope)
		VALUES ({:uid},{:collection},{:owner},{:label},{:scope})`).Bind(dbx.Params{"uid": uid, "collection": e.Auth.Collection().Name, "owner": e.Auth.Id, "label": in.Label, "scope": string(encoded)}).Execute()
	if err != nil {
		return e.InternalServerError("Could not issue credential", nil)
	}
	e.Response.Header().Set("Cache-Control", "no-store")
	return e.JSON(http.StatusCreated, object{"uid": uid, "apikey": secretFor(uid, e.Auth)})
}

func listKeys(e *core.RequestEvent) error {
	if !actorAllowed(e.Auth) {
		return e.ForbiddenError("Inactive owner", nil)
	}
	var rows []keyRow
	err := e.App.DB().NewQuery("SELECT uid,label,scope FROM dns_interface_keys WHERE owner_collection={:c} AND owner={:o} ORDER BY uid").Bind(dbx.Params{"c": e.Auth.Collection().Name, "o": e.Auth.Id}).All(&rows)
	if err != nil {
		return e.InternalServerError("Could not list credentials", nil)
	}
	out := make([]object, 0, len(rows))
	for _, r := range rows {
		out = append(out, object{"uid": r.UID, "label": r.Label, "scope": json.RawMessage(r.Scope)})
	}
	return e.JSON(200, out)
}

func revokeKey(e *core.RequestEvent) error {
	if !actorAllowed(e.Auth) {
		return e.ForbiddenError("Inactive owner", nil)
	}
	_, err := e.App.DB().NewQuery("DELETE FROM dns_interface_keys WHERE uid={:id} AND owner_collection={:c} AND owner={:o}").Bind(dbx.Params{"id": e.Request.PathValue("uid"), "c": e.Auth.Collection().Name, "o": e.Auth.Id}).Execute()
	if err != nil {
		return e.InternalServerError("Could not revoke credential", nil)
	}
	return e.NoContent(http.StatusNoContent)
}

// A request may contain multiple mutations. Recheck the key and the owner during long-running batches.
func activeGrant(e *core.RequestEvent) bool {
	return activeGrantIn(e, e.App)
}

func activeGrantIn(e *core.RequestEvent, app core.App) bool {
	uid, _ := e.Get(keyUID).(string)
	if uid == "" || !apiEnabled(e.Auth) {
		return false
	}
	var existing string
	if err := app.DB().NewQuery("SELECT scope FROM dns_interface_keys WHERE uid={:id} AND owner_collection={:c} AND owner={:o}").Bind(dbx.Params{"id": uid, "c": e.Auth.Collection().Name, "o": e.Auth.Id}).WithContext(e.Request.Context()).Row(&existing); err != nil || existing != e.Get(keyScopeJSON) {
		return false
	}
	r, err := app.FindRecordById(e.Auth.Collection().Name, e.Auth.Id)
	return err == nil && apiEnabled(r) && r.TokenKey() == e.Auth.TokenKey()
}

const keyUID = "dns.interface.key.uid"
const keyScopeJSON = "dns.interface.key.json"

func signed(uid, timestamp, secret string) string {
	sum := md5.Sum([]byte(uid + timestamp + secret))
	return hex.EncodeToString(sum[:])
}

func authorize(iface string) *hook.Handler[*core.RequestEvent] {
	return &hook.Handler[*core.RequestEvent]{Priority: apis.DefaultLoadAuthTokenMiddlewarePriority - 1, Func: func(e *core.RequestEvent) error {
		deny := func() error {
			if iface == "mcp" {
				e.Response.Header().Set("WWW-Authenticate", `Bearer realm="dnsmgr-mcp"`)
				return e.JSON(401, rpcError(nil, -32001, "Invalid interface credential"))
			}
			return e.JSON(403, object{"code": -1, "msg": "Invalid interface credential"})
		}
		e.Response.Header().Set("Cache-Control", "no-store")
		// PocketBase records RequestURI and Referer. These endpoints have no query parameters.
		e.Request.Header.Del("Referer")
		if e.Request.URL.RawQuery != "" || e.Request.URL.ForceQuery {
			e.Request.URL.RawQuery = ""
			e.Request.URL.ForceQuery = false
			e.Request.RequestURI = e.Request.URL.RequestURI()
			return deny()
		}
		var uid, proof, stamp, nonce string
		var ts int64
		header := e.Request.Header.Get("Authorization")
		if iface == "mcp" {
			kind, token, ok := strings.Cut(header, " ")
			if !ok || !strings.EqualFold(kind, "Bearer") {
				return deny()
			}
			uid, proof, ok = strings.Cut(token, ":")
			if !ok {
				return deny()
			}
		} else if iface == "api" && header == "" {
			// Authenticate POST data only. Query strings may be recorded in access logs.
			e.Request.Body = http.MaxBytesReader(e.Response, e.Request.Body, bodyLimit)
			if e.Request.ParseForm() != nil {
				return deny()
			}
			for _, v := range e.Request.PostForm {
				if len(v) != 1 {
					return deny()
				}
			}
			uid, proof, stamp = e.Request.PostForm.Get("uid"), e.Request.PostForm.Get("sign"), e.Request.PostForm.Get("timestamp")
			var err error
			ts, err = strconv.ParseInt(stamp, 10, 64)
			now := time.Now().Unix()
			if err != nil || ts < now-300 || ts > now+300 {
				return deny()
			}
		} else {
			return deny()
		}
		if _, err := strconv.ParseUint(uid, 10, 53); err != nil || proof == "" {
			return deny()
		}
		var row keyRow
		err := e.App.DB().NewQuery("SELECT uid,owner_collection,owner,scope FROM dns_interface_keys WHERE uid={:uid}").Bind(dbx.Params{"uid": uid}).One(&row)
		if err != nil || (row.Collection != dnsauth.Members && row.Collection != core.CollectionNameSuperusers) {
			return deny()
		}
		actor, err := e.App.FindRecordById(row.Collection, row.Owner)
		if err != nil || !apiEnabled(actor) || actor.TokenKey() == "" {
			return deny()
		}
		expected := secretFor(uid, actor)
		if stamp != "" {
			form := e.Request.PostForm
			switch form.Get("sign_version") {
			case "", "1":
				// Legacy signatures do not bind the operation or payload. Only ordinary read endpoints accept them.
				path := e.Request.URL.Path
				if !(path == "/api/domain" || strings.HasPrefix(path, "/api/domain/") && form.Get("loginurl") != "1" || strings.HasPrefix(path, "/api/record/data/")) {
					return deny()
				}
				expected = signed(uid, stamp, expected)
			case "2":
				nonce = form.Get("nonce")
				if len(nonce) != 32 || strings.ToLower(nonce) != nonce {
					return deny()
				}
				if _, err := hex.DecodeString(nonce); err != nil {
					return deny()
				}
				expected = dnssign.Sign(e.Request.URL.EscapedPath(), form, expected)
			default:
				return deny()
			}
		}
		var s scope
		if !hmac.Equal([]byte(expected), []byte(proof)) || json.Unmarshal([]byte(row.Scope), &s) != nil || !slices.Contains(s.Interfaces, iface) {
			return deny()
		}
		if nonce != "" {
			// Claim once before dispatch, even if the provider or client subsequently times out.
			err := e.App.RunInTransaction(func(tx core.App) error {
				ctx := e.Request.Context()
				now := time.Now().Unix()
				if ts < now-300 || ts > now+300 {
					return errors.New("expired")
				}
				if _, err := tx.DB().NewQuery("DELETE FROM dns_interface_nonces WHERE expires < {:now}").Bind(dbx.Params{"now": now}).WithContext(ctx).Execute(); err != nil {
					return err
				}
				_, err := tx.DB().NewQuery("INSERT INTO dns_interface_nonces(uid,nonce,expires) VALUES({:uid},{:nonce},{:end})").Bind(dbx.Params{"uid": uid, "nonce": nonce, "end": ts + 300}).WithContext(ctx).Execute()
				return err
			})
			if err != nil {
				return deny()
			}
		}
		// Load before PB's IP-allowlist check. Only these endpoint handlers consume this scope.
		e.Auth = actor
		e.Set(scopeKey, s)
		e.Set(keyUID, uid)
		e.Set(keyScopeJSON, row.Scope)
		return e.Next()
	}}
}
