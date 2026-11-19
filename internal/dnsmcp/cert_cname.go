package dnsmcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"strings"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"golang.org/x/net/idna"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/domain"
)

var certCnameTools = []toolDefinition{
	{"cert_cname_query", "List ACME challenge CNAME delegations in the granted source and target zones.", []operation{{"list", "cert.cname.read"}}, []string{"kw", "sortName", "sortOrder", "offset", "limit"}},
	{"cert_cname_manage", "Manage ACME challenge delegations and check their published CNAME. For add, did is the target zone. Supply source_zone_id when the source name matches multiple accounts.", []operation{{"add", "cert.cname.add"}, {"edit", "cert.cname.edit"}, {"del", "cert.cname.delete"}, {"check", "cert.cname.check"}}, []string{"id", "domain", "rr", "did", "source_zone_id"}},
}

var cnameHostLabel = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)

var cnameOwnerLabel = regexp.MustCompile(`^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$`)

func cnameDomain(name string) string {
	n, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if err != nil || !strings.Contains(n, ".") || len(n) > 253 || net.ParseIP(n) != nil {
		return ""
	}
	n = strings.ToLower(n)
	for _, label := range strings.Split(n, ".") {
		if !cnameHostLabel.MatchString(label) {
			return ""
		}
	}
	return n
}

type certCnameRow struct {
	ID         string `db:"id" json:"id"`
	SourceID   string `db:"source_zone_id" json:"source_zone_id"`
	SourceName string `db:"source_name" json:"-"`
	Domain     string `db:"domain" json:"domain"`
	TargetID   string `db:"target_zone_id" json:"did"`
	TargetName string `db:"target_name" json:"cnamedomain"`
	RR         string `db:"rr" json:"rr"`
	Status     int    `db:"status" json:"status"`
	Revision   int    `db:"revision" json:"-"`
	Created    string `db:"created" json:"addtime"`
	Host       string `db:"-" json:"host"`
	Record     string `db:"-" json:"record"`
}

func (r *certCnameRow) project() {
	r.Host = strings.TrimSuffix("_acme-challenge."+r.Domain, "."+r.SourceName)
	r.Record = r.RR + "." + r.TargetName
}

// Use the common catalog and authorization checks even for keys owned by a
// superuser. The current catalog name must match the identity saved at creation.
func cnameZones(e *core.RequestEvent, app core.App, grant scope, write bool) (map[string]string, error) {
	zones := make(map[string]string, len(grant.Zones))
	ev := &core.RequestEvent{App: app, Auth: e.Auth}
	ev.Request = e.Request
	for _, id := range grant.Zones {
		zone, err := dnsauth.GetZone(ev, id, write)
		if errors.Is(err, domain.ErrRecordNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if name := cnameDomain(zone.Name); name != "" {
			zones[id] = name
		}
	}
	return zones, nil
}

const cnameFrom = ` FROM dns_cert_cnames c
	JOIN json_each({:zones}) s ON c.source_zone_id=s.key AND c.source_name=s.value
	JOIN json_each({:zones}) t ON c.target_zone_id=t.key AND c.target_name=t.value`

func cnameSource(zones map[string]string, name, id string) string {
	winner, length := "", 0
	for z, suffix := range zones {
		if name != suffix && !strings.HasSuffix(name, "."+suffix) {
			continue
		}
		if len(suffix) > length {
			winner, length = z, len(suffix)
		} else if len(suffix) == length && z != id && winner != id {
			winner = ""
		}
		if len(suffix) == length && z == id {
			winner = z
		}
	}
	if id != "" && winner != id {
		return ""
	}
	return winner
}

func cnameList(ctx context.Context, app core.App, zones map[string]string, args object) (object, *opError) {
	offset, limit, ok := paging(args)
	if !ok {
		return nil, invalid
	}
	encoded, _ := json.Marshal(zones)
	params := dbx.Params{"zones": string(encoded), "kw": strings.ToLower(str(args, "kw")), "limit": limit, "offset": offset}
	where := cnameFrom + " WHERE instr(c.domain,{:kw})>0"
	var total int
	if err := app.DB().NewQuery("SELECT count(*)" + where).Bind(params).WithContext(ctx).Row(&total); err != nil {
		return nil, cnameDBError
	}
	sortColumn := map[string]string{"id": "c.id", "domain": "c.domain", "addtime": "c.created", "status": "c.status"}[str(args, "sortName")]
	if sortColumn == "" {
		sortColumn = "c.id"
	}
	direction := " DESC"
	if strings.EqualFold(str(args, "sortOrder"), "asc") {
		direction = " ASC"
	}
	rows := []certCnameRow{}
	err := app.DB().NewQuery("SELECT c.*" + where + " ORDER BY " + sortColumn + direction + ",c.id LIMIT {:limit} OFFSET {:offset}").Bind(params).WithContext(ctx).All(&rows)
	if err != nil {
		return nil, cnameDBError
	}
	for i := range rows {
		rows[i].project()
	}
	return object{"total": total, "rows": rows}, nil
}

var (
	cnameDBError  = &opError{500, "Could not access CNAME delegation catalog"}
	cnameConflict = &opError{409, "Conflicting or changed CNAME delegation"}
)

// runCnameCatalog commits the scope lookup, count/page or mutation in the same
// snapshot. DNS checks run between two snapshots and verify the row revision.
func runCnameCatalog(e *core.RequestEvent, grant scope, write bool, fn func(core.App, map[string]string) (object, *opError)) (object, *opError) {
	var result object
	var failure *opError
	err := e.App.RunInTransaction(func(tx core.App) error {
		zones, err := cnameZones(e, tx, grant, write)
		if err != nil {
			return err
		}
		result, failure = fn(tx, zones)
		if failure != nil {
			return errors.New(failure.message)
		}
		return nil
	})
	if failure != nil {
		return nil, failure
	}
	if err != nil {
		return nil, cnameDBError
	}
	return result, nil
}

func (s service) certCname(e *core.RequestEvent, tool, action string, args object, grant scope) (object, *opError) {
	if !e.HasSuperuserAuth() {
		return nil, denied
	}
	ctx := e.Request.Context()
	if tool == "cert_cname_query" && action == "list" {
		return runCnameCatalog(e, grant, false, func(tx core.App, zones map[string]string) (object, *opError) {
			return cnameList(ctx, tx, zones, args)
		})
	}
	if tool != "cert_cname_manage" {
		return nil, invalid
	}
	var check *certCnameRow
	out, problem := runCnameCatalog(e, grant, true, func(tx core.App, zones map[string]string) (object, *opError) {
		var r certCnameRow
		if action == "add" {
			r.ID = core.GenerateDefaultRandomId()
			r.Domain = cnameDomain(str(args, "domain"))
			if r.Domain == "" || len("_acme-challenge."+r.Domain) > 253 {
				return nil, invalid
			}
			r.SourceID = cnameSource(zones, r.Domain, str(args, "source_zone_id"))
			if r.SourceID == "" {
				return nil, missing
			}
			r.SourceName = zones[r.SourceID]
		} else {
			row, problem := cnameByID(ctx, tx, zones, str(args, "id"))
			if problem != nil {
				return nil, problem
			}
			r = row
			switch action {
			case "check":
				r.project()
				check = &r
				return nil, nil
			case "del":
				_, err := tx.DB().Delete("dns_cert_cnames", dbx.HashExp{"id": r.ID}).WithContext(ctx).Execute()
				if err != nil {
					return nil, cnameDBError
				}
				return object{"code": 0}, nil
			case "edit":
			default:
				return nil, invalid
			}
		}

		oldRR, oldTarget := r.RR, r.TargetID
		if _, present := args["did"]; present {
			r.TargetID = str(args, "did")
		}
		if _, present := args["rr"]; present {
			r.RR = strings.ToLower(strings.TrimSpace(str(args, "rr")))
		}
		r.TargetName = zones[r.TargetID]
		if r.TargetName == "" {
			return nil, missing
		}
		if len(r.RR)+1+len(r.TargetName) > 253 {
			return nil, invalid
		}
		for _, label := range strings.Split(r.RR, ".") {
			if !cnameOwnerLabel.MatchString(label) {
				return nil, invalid
			}
		}
		if "_acme-challenge."+r.Domain == r.RR+"."+r.TargetName {
			return nil, invalid
		}
		fields := dbx.Params{"target_zone_id": r.TargetID, "target_name": r.TargetName, "rr": r.RR}
		var q *dbx.Query
		if action == "add" {
			fields["id"], fields["domain"], fields["source_zone_id"], fields["source_name"] = r.ID, r.Domain, r.SourceID, r.SourceName
			q = tx.DB().Insert("dns_cert_cnames", fields)
		} else {
			if oldRR != r.RR || oldTarget != r.TargetID {
				fields["status"] = 0
			}
			fields["revision"] = r.Revision + 1
			q = tx.DB().Update("dns_cert_cnames", fields, dbx.HashExp{"id": r.ID})
		}
		if _, err := q.WithContext(ctx).Execute(); err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				return nil, cnameConflict
			}
			return nil, cnameDBError
		}
		return object{"code": 0, "id": r.ID}, nil
	})
	if problem != nil || check == nil {
		return out, problem
	}

	live, err := publishedCname(ctx, "_acme-challenge."+check.Domain, check.Record)
	if err != nil {
		return nil, &opError{502, "DNS lookup failed"}
	}
	return runCnameCatalog(e, grant, true, func(tx core.App, zones map[string]string) (object, *opError) {
		r, problem := cnameByID(ctx, tx, zones, check.ID)
		if problem != nil {
			return nil, problem
		}
		if r.Revision != check.Revision {
			return nil, cnameConflict
		}
		status := 0
		if live {
			status = 1
		}
		_, err := tx.DB().Update("dns_cert_cnames", dbx.Params{"status": status, "revision": r.Revision + 1}, dbx.HashExp{"id": r.ID}).WithContext(ctx).Execute()
		if err != nil {
			return nil, cnameDBError
		}
		return object{"code": 0, "status": status}, nil
	})
}

func cnameByID(ctx context.Context, tx core.App, zones map[string]string, id string) (certCnameRow, *opError) {
	var r certCnameRow
	encoded, _ := json.Marshal(zones)
	err := tx.DB().NewQuery("SELECT c.*" + cnameFrom + " WHERE c.id={:id}").Bind(dbx.Params{"zones": string(encoded), "id": id}).WithContext(ctx).One(&r)
	if errors.Is(err, sql.ErrNoRows) {
		return r, missing
	}
	if err != nil {
		return r, cnameDBError
	}
	return r, nil
}
