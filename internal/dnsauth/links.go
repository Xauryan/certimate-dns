package dnsauth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	"github.com/pocketbase/pocketbase/tools/security"

	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/internal/rest/resp"
)

const ticketLifetime = 5 * time.Minute
const zoneSessionLifetime = time.Hour

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func issuerStamp(owner *core.Record) string {
	return digest(owner.TokenKey() + ":" + owner.Collection().AuthToken.Secret)
}

// IssueQuickLink creates a single-use ticket. Interface callers must pass the
// originating key UID so that revoking that key also revokes its sessions.
func IssueQuickLink(e *core.RequestEvent, zoneID string, write bool, sourceKeyUID string) (string, error) {
	if e.Auth == nil || !(e.Auth.IsSuperuser() || e.Auth.Collection().Name == Members) {
		return "", domain.NewError(403, "member or administrator required")
	}
	if requestKey, _ := e.Get("dns.interface.key.uid").(string); requestKey != "" && requestKey != sourceKeyUID {
		return "", domain.NewError(403, "interface credential scope required")
	}
	if sourceKeyUID != "" && write {
		return "", domain.NewError(403, "interface links are read-only")
	}
	code := security.RandomString(48)
	err := e.App.RunInTransaction(func(tx core.App) error {
		c, err := tx.FindCollectionByNameOrId(ZoneSessions)
		if err != nil {
			return err
		}
		session := core.NewRecord(c)
		session.SetRandomPassword()
		session.Set("zone", zoneID)
		session.Set("writable", write)
		session.Set("issuerCollection", e.Auth.Collection().Name)
		session.Set("issuer", e.Auth.Id)
		session.Set("issuerStamp", issuerStamp(e.Auth))
		session.Set("interfaceKey", sourceKeyUID)
		session.Set("ticketHash", digest(code))
		now := time.Now()
		session.Set("ticketUntil", now.Add(ticketLifetime).Unix())
		session.Set("expiresAt", now.Add(zoneSessionLifetime).Unix())
		check := &core.RequestEvent{App: tx, Auth: session}
		check.Request = e.Request
		if _, err = GetZone(check, zoneID, write); err != nil {
			return err
		}
		if _, err = tx.DB().NewQuery("DELETE FROM dns_zone_sessions WHERE expiresAt <= {:now} OR (ticketHash != '' AND ticketUntil <= {:now})").
			Bind(dbx.Params{"now": now.Unix()}).Execute(); err != nil {
			return err
		}
		return tx.Save(session)
	})
	if err != nil {
		var de *domain.Error
		if errors.As(err, &de) {
			return "", de
		}
		return "", domain.NewError(500, "could not create zone login")
	}
	return "#/dns-member?ticket=" + code, nil
}

func delegatedScope(e *core.RequestEvent) (string, dbx.Params, error) {
	s := e.Auth
	if int64(s.GetInt("expiresAt")) <= time.Now().Unix() {
		return "", nil, domain.ErrRecordNotFound
	}
	collection := s.GetString("issuerCollection")
	if collection != Members && collection != core.CollectionNameSuperusers {
		return "", nil, domain.ErrRecordNotFound
	}
	owner, err := e.App.FindRecordById(collection, s.GetString("issuer"))
	if err != nil || issuerStamp(owner) != s.GetString("issuerStamp") {
		return "", nil, domain.ErrRecordNotFound
	}
	base, args, err := ownerScope(owner)
	if err != nil {
		return "", nil, err
	}
	args["delegatedZone"] = s.GetString("zone")
	args["delegatedWrite"] = s.GetBool("writable")
	query := `SELECT id, accessId, provider, zoneId, name, status, 0 AS quickLoginEnabled, (canWrite AND {:delegatedWrite}) AS canWrite FROM (` + base + `)
		WHERE id = {:delegatedZone} AND EXISTS (SELECT 1 FROM dnsZone WHERE id = {:delegatedZone} AND quickLoginEnabled = 1)`
	if key := s.GetString("interfaceKey"); key != "" {
		if collection == Members && !owner.GetBool("apiEnabled") {
			return "", nil, domain.ErrRecordNotFound
		}
		args["sourceKey"] = key
		args["ownerID"] = owner.Id
		args["collection"] = collection
		query += ` AND EXISTS (SELECT 1 FROM dns_interface_keys k
			WHERE k.uid = {:sourceKey} AND k.owner = {:ownerID} AND k.owner_collection = {:collection}
			AND {:delegatedZone} IN (SELECT value FROM json_each(k.scope, '$.zones'))
			AND (SELECT COUNT(DISTINCT value) FROM json_each(k.scope,'$.actions')
				WHERE value IN ('domain.login','record.read','domain.read')) = 3)`
	}
	return query, args, nil
}

func bindLinks(api *router.RouterGroup[*core.RequestEvent]) {
	api.POST("/dns-member/zones/{id}/links", func(e *core.RequestEvent) error {
		var data struct {
			Write bool `json:"write"`
		}
		if err := e.BindBody(&data); err != nil {
			return resp.Err(e, domain.ErrInvalidParams)
		}
		link, err := IssueQuickLink(e, e.Request.PathValue("id"), data.Write, "")
		if err != nil {
			return resp.Err(e, err)
		}
		e.Response.Header().Set("Cache-Control", "no-store")
		return resp.Ok(e, map[string]string{"link": link})
	}).Bind(apis.RequireAuth(Members, core.CollectionNameSuperusers), apis.BodyLimit(2048))
	api.POST("/dns-member/redeem", func(e *core.RequestEvent) error {
		var data struct {
			Ticket string `json:"ticket"`
		}
		denied := domain.NewError(403, "zone login link is invalid or expired")
		if err := e.BindBody(&data); err != nil || len(data.Ticket) != 48 {
			return resp.Err(e, denied)
		}
		var token, id string
		err := e.App.RunInTransaction(func(tx core.App) error {
			session, err := tx.FindFirstRecordByData(ZoneSessions, "ticketHash", digest(data.Ticket))
			if err != nil || session.GetInt("ticketUntil") <= int(time.Now().Unix()) {
				return denied
			}
			check := &core.RequestEvent{App: tx, Auth: session}
			check.Request = e.Request
			if _, err = GetZone(check, session.GetString("zone"), false); err != nil {
				return denied
			}
			changed, err := tx.DB().NewQuery("UPDATE dns_zone_sessions SET ticketHash='' WHERE id={:id} AND ticketHash={:hash}").
				Bind(dbx.Params{"id": session.Id, "hash": digest(data.Ticket)}).Execute()
			if err != nil {
				return err
			}
			if n, err := changed.RowsAffected(); err != nil || n != 1 {
				return denied
			}
			token, err = session.NewStaticAuthToken(time.Until(time.Unix(int64(session.GetInt("expiresAt")), 0)))
			id = session.Id
			return err
		})
		if err != nil {
			return resp.Err(e, denied)
		}
		e.Response.Header().Set("Cache-Control", "no-store")
		return resp.Ok(e, map[string]any{"token": token, "record": map[string]string{"id": id, "collectionName": ZoneSessions}})
	}).Bind(apis.BodyLimit(2048))
}
