package dnsmcp

import (
	"crypto/tls"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/dnscert"
	"github.com/certimate-go/certimate/internal/domain"
	xcert "github.com/certimate-go/certimate/pkg/utils/cert"
)

type certOrder struct {
	LegacyID      int64  `db:"api_id" json:"api_id"`
	ID            string `db:"id" json:"id"`
	AccessID      string `db:"access_id" json:"aid"`
	Domain        string `db:"domain" json:"domain"`
	SourceZoneID  string `db:"primary_zone_id" json:"zone_id"`
	Provider      string `db:"provider" json:"type"`
	Algorithm     string `db:"algorithm" json:"algorithm"`
	State         string `db:"state" json:"state"`
	CertificateID string `db:"certificate_id" json:"-"`
	Version       int    `db:"version" json:"version"`
	Status        int    `db:"status" json:"status"`
}

const certOrderColumns = `(SELECT id FROM dns_interface_cert_orders WHERE order_id=o.id) AS api_id,o.id,o.access_id,o.domain,o.primary_zone_id,o.provider,o.algorithm,o.state,o.certificate_id,o.version,
	CASE o.state WHEN 'draft' THEN 0 WHEN 'creating' THEN 0 WHEN 'reserved' THEN 0
	WHEN 'submitting' THEN 1 WHEN 'pending' THEN 2 WHEN 'issued' THEN 3 WHEN 'revoking' THEN 3 WHEN 'revoked' THEN 4
	WHEN 'expired' THEN 7 ELSE 5 END AS status`

func certOrderRow(app core.App, id string) (certOrder, *opError) {
	var row certOrder
	err := app.DB().NewQuery("SELECT " + certOrderColumns + " FROM dns_cert_orders o WHERE o.id={:id} AND o.state<>'deleted'").Bind(dbx.Params{"id": id}).One(&row)
	if errors.Is(err, sql.ErrNoRows) {
		return row, missing
	}
	if err != nil {
		return row, certStoreError
	}
	return row, nil
}

var certStoreError = &opError{500, "Certificate service unavailable"}

func certOrderAllowed(e *core.RequestEvent, grant scope, order certOrder, write bool) bool {
	if !e.HasSuperuserAuth() || !grant.Global || order.SourceZoneID == "" || !slices.Contains(grant.Zones, order.SourceZoneID) || !slices.Contains(grant.Accounts, order.AccessID) {
		return false
	}
	zone, err := dnsauth.GetZone(e, order.SourceZoneID, write)
	if err != nil || !certWithinZone(order.Domain, zone.Name) {
		return false
	}
	var active int
	err = e.App.DB().NewQuery("SELECT count(*) FROM access WHERE id={:id} AND provider={:provider} AND deleted='' AND reserve IN ('','ca')").
		Bind(dbx.Params{"id": order.AccessID, "provider": order.Provider}).WithContext(e.Request.Context()).Row(&active)
	return err == nil && active == 1
}

func certWithinZone(name, zone string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	return name != "" && zone != "" && (name == zone || strings.HasSuffix(name, "."+zone))
}

func certOrderQuery(e *core.RequestEvent, grant scope, action string, args object) (object, *opError) {
	switch action {
	case "list":
		return certOrderList(e, grant, args)
	case "show_log", "get":
	default:
		return nil, invalid
	}
	id := str(args, "id")
	if id == "" && action == "show_log" {
		id = str(args, "processid")
	}
	if id == "" {
		return nil, invalid
	}
	isLegacy := false
	if action == "get" && e.Request.URL.Path == "/api/cert/order" {
		// Signed DNSMgr clients can only store integer order IDs. The MCP list
		// supplies the stable API alias alongside each native order ID.
		if n, err := strconv.ParseInt(id, 10, 53); err == nil && n > 0 && strconv.FormatInt(n, 10) == id {
			var local string
			err := e.App.DB().NewQuery("SELECT order_id FROM dns_interface_cert_orders WHERE id={:id}").Bind(dbx.Params{"id": n}).WithContext(e.Request.Context()).Row(&local)
			if errors.Is(err, sql.ErrNoRows) {
				return nil, missing
			}
			if err != nil {
				return nil, certStoreError
			}
			isLegacy = true
			id = local
		}
	}
	row, problem := certOrderRow(e.App, id)
	if problem != nil {
		return nil, problem
	}
	if !certOrderAllowed(e, grant, row, false) {
		return nil, missing
	}
	if action == "show_log" {
		page, ok := number(args, "page", 1, 1, 1000000)
		if !ok {
			return nil, invalid
		}
		events, err := dnscert.OrderEvents(e.Request.Context(), e.App, id, page)
		if err != nil {
			return nil, certStoreError
		}
		return object{"code": 0, "data": events.Items, "total": events.Total}, nil
	}
	record, problem := certReadMaterial(e, grant, row)
	if problem != nil {
		return nil, problem
	}
	chain, key := record.GetString("certificate"), record.GetString("privateKey")
	data := object{"id": id, "crt": chain, "key": key, "issuetime": record.GetString("validityNotBefore"), "expiretime": record.GetString("validityNotAfter"), "domains": []string{row.Domain}}
	if isLegacy {
		data["id"] = row.LegacyID
	}
	include := e.Request.URL.Path == "/api/cert/order"
	if raw, exists := args["include_pfx"]; exists {
		var ok bool
		include, ok = certBool(raw)
		if !ok {
			return nil, invalid
		}
	}
	if include {
		pfx, err := xcert.TransformCertificateFromPEMToPFX(chain, key, "123456", nil)
		if err != nil {
			return nil, certStoreError
		}
		data["pfx"] = base64.StdEncoding.EncodeToString(pfx)
	}
	if !activeGrant(e) || !certOrderAllowed(e, grant, row, false) {
		return nil, missing
	}
	e.Response.Header().Set("Cache-Control", "no-store")
	return object{"code": 0, "data": data}, nil
}

func certBool(value any) (bool, bool) {
	switch value {
	case true, "1", "true", float64(1):
		return true, true
	case false, "0", "false", float64(0):
		return false, true
	}
	return false, false
}

// The commercial issuer accepts exactly one DNS identity. Revalidate the stored
// key, leaf and SANs before disclosing material or passing it to any deployer.
func certReadMaterial(e *core.RequestEvent, grant scope, row certOrder) (*core.Record, *opError) {
	if !certOrderAllowed(e, grant, row, false) || row.State != "issued" || row.CertificateID == "" {
		return nil, missing
	}
	record, err := e.App.FindRecordById(domain.CollectionNameCertificate, row.CertificateID)
	if err != nil || record.GetString("deleted") != "" || record.GetBool("isRevoked") {
		return nil, missing
	}
	pair, err := tls.X509KeyPair([]byte(record.GetString("certificate")), []byte(record.GetString("privateKey")))
	if err != nil || pair.Leaf == nil {
		return nil, certStoreError
	}
	leaf := pair.Leaf
	if leaf.IsCA || len(leaf.DNSNames) != 1 || !strings.EqualFold(leaf.DNSNames[0], row.Domain) ||
		len(leaf.IPAddresses)+len(leaf.EmailAddresses)+len(leaf.URIs) != 0 ||
		(leaf.Subject.CommonName != "" && !strings.EqualFold(leaf.Subject.CommonName, row.Domain)) {
		return nil, denied
	}
	// Go exposes DNS/IP/email/URI SANs. Refuse opaque GeneralName variants
	// as well, since a DNS zone grant cannot authorize those identities.
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			continue
		}
		var names []asn1.RawValue
		rest, err := asn1.Unmarshal(ext.Value, &names)
		if err != nil || len(rest) != 0 || len(names) != 1 || names[0].Class != asn1.ClassContextSpecific || names[0].Tag != 2 || names[0].IsCompound {
			return nil, denied
		}
	}
	return record, nil
}

const certOrdersFrom = ` FROM dns_cert_orders o
	JOIN access issuer ON issuer.id=o.access_id AND issuer.provider=o.provider AND issuer.deleted=''
	JOIN dnsZone z ON z.id=o.primary_zone_id AND z.present=1
	JOIN dnsAccount za ON za.id=z.accountRef AND za.disabled=0
	JOIN access a ON a.id=za.accessRef AND a.id=za.id AND a.deleted=''
	LEFT JOIN certificate cert ON cert.id=o.certificate_id AND cert.deleted=''
	WHERE issuer.reserve IN ('','ca') AND o.state<>'deleted' AND o.access_id IN (SELECT value FROM json_each({:accounts}))
	AND z.id IN (SELECT value FROM json_each({:zones}))
	AND (lower(o.domain)=lower(z.name) OR substr(lower(o.domain),-length(z.name)-1)='.'||lower(z.name))`

func certOrderList(e *core.RequestEvent, grant scope, args object) (object, *opError) {
	offset, limit, ok := paging(args)
	if !ok {
		return nil, invalid
	}
	accounts, _ := json.Marshal(grant.Accounts)
	zones, _ := json.Marshal(grant.Zones)
	params := dbx.Params{"accounts": string(accounts), "zones": string(zones)}
	from := certOrdersFrom
	for _, filter := range []struct{ key, column string }{{"aid", "o.access_id"}, {"id", "o.id"}, {"type", "o.provider"}} {
		if v := str(args, filter.key); v != "" {
			if filter.key == "type" && v == "tencent" {
				v = "tencentcloud"
			}
			from += " AND " + filter.column + "={:" + filter.key + "}"
			params[filter.key] = v
		}
	}
	if v := str(args, "domain"); v != "" {
		from += " AND instr(lower(o.domain),lower({:domain}))>0"
		params["domain"] = v
	}
	if v := str(args, "status"); v != "" {
		switch v {
		case "0":
			from += " AND o.state IN ('draft','creating','reserved')"
		case "1":
			from += " AND o.state='submitting'"
		case "2":
			from += " AND o.state='pending'"
		case "3":
			from += " AND o.state IN ('issued','revoking')"
		case "4":
			from += " AND o.state='revoked'"
		case "5":
			from += " AND o.state IN ('failed','cancelled','cancelling')"
		case "6":
			from += " AND julianday(cert.validityNotAfter) BETWEEN julianday('now') AND julianday('now','+7 days')"
		case "7":
			from += " AND (o.state='expired' OR julianday(cert.validityNotAfter)<julianday('now'))"
		default:
			return nil, invalid
		}
	}
	rows := []certOrder{}
	var total int
	err := e.App.RunInTransaction(func(tx core.App) error {
		if err := tx.DB().NewQuery("SELECT count(*)" + from).Bind(params).WithContext(e.Request.Context()).Row(&total); err != nil {
			return err
		}
		params["limit"], params["offset"] = limit, offset
		return tx.DB().NewQuery("SELECT " + certOrderColumns + from + " ORDER BY o.created DESC,o.id LIMIT {:limit} OFFSET {:offset}").Bind(params).WithContext(e.Request.Context()).All(&rows)
	})
	if err != nil {
		return nil, certStoreError
	}
	return object{"rows": rows, "total": total}, nil
}
