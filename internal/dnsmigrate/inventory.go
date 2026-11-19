// The related inventory preserves source identity and references for administrator
// review. It never creates sign-in identities, grants, orders or deployments.
package dnsmigrate

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Related struct {
	Kind         string `json:"kind"`
	ID           int64  `json:"id"`
	ParentID     int64  `json:"parentId,omitempty"`
	OrderID      int64  `json:"orderId,omitempty"`
	Domain       string `json:"domain,omitempty"`
	RR           string `json:"rr,omitempty"`
	State        int    `json:"state,omitempty"`
	CategoryName string `json:"categoryName,omitempty"`
}

type HistoryCounts struct {
	Configuration int64 `json:"configRows"`
	Operations    int64 `json:"logRows"`
	Monitor       int64 `json:"monitorLogRows"`
}

// These projections contain reference IDs, names and numeric state. Free-form
// payloads are excluded because config, account settings, record snapshots, history and certificate
// material may all contain credentials or private keys.
var relatedTables = []struct {
	kind, parent, columns, reason string
}{
	{"domain_category", "", "id,0,0,'','',sort,name", "review category and local grouping"},
	{"domain_alias", "domain", "id,did,0,name,'',0", "review alias in target catalog"},
	{"user", "", "id,0,0,'','',status", "create a target identity and confirm its role"},
	{"permission", "user", "id,uid,0,domain,COALESCE(sub,''),0", "review member and zone grants"},
	{"cert_account", "", "id,0,0,'','',deploy", "configure certificate or deployment credentials separately"},
	{"cert_order", "cert_account", "id,aid,0,'','',status", "review order and certificate transfer"},
	{"cert_domain", "cert_order", "id,oid,0,domain,'',sort", "review certificate name against order"},
	{"cert_deploy", "cert_account", "id,aid,oid,'','',active", "review deployment dependencies before creating workflow"},
	{"cert_cname", "domain", "id,did,0,domain,rr,status", "verify delegated DNS challenge record"},
}

type tableReader func(string, string, func(*sql.Rows) error) error

func (m *Manifest) readRelated(read tableReader) error {
	for _, table := range relatedTables {
		if err := read(table.kind, table.columns, func(rows *sql.Rows) error {
			r := Related{Kind: table.kind}
			fields := []any{&r.ID, &r.ParentID, &r.OrderID, &r.Domain, &r.RR, &r.State}
			if r.Kind == "domain_category" {
				fields = append(fields, &r.CategoryName)
			}
			if err := rows.Scan(fields...); err != nil {
				return err
			}
			m.Related = append(m.Related, r)
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manifest) validateRelated(zones map[int64]bool) error {
	if h := m.History; h != nil && (h.Configuration < 0 || h.Operations < 0 || h.Monitor < 0) {
		return errors.New("invalid source row counts")
	}
	ids := map[string]map[int64]bool{"domain": zones}
	for _, table := range relatedTables {
		ids[table.kind] = map[int64]bool{}
	}
	for i := range m.Related {
		r := &m.Related[i]
		kindIDs, ok := ids[r.Kind]
		if !ok || r.Kind == "domain" || r.ID <= 0 || kindIDs[r.ID] {
			return fmt.Errorf("unknown, invalid or duplicate related object %d", r.ID)
		}
		kindIDs[r.ID] = true
		if (r.Kind == "domain_category") != (r.CategoryName != "") || strings.TrimSpace(r.CategoryName) != r.CategoryName || strings.IndexFunc(r.CategoryName, unicode.IsControl) >= 0 || utf8.RuneCountInString(r.CategoryName) > 50 {
			return fmt.Errorf("invalid category name on %s %d", r.Kind, r.ID)
		}
		if r.Domain != "" {
			name, err := canonicalName(r.Domain, true)
			if err != nil || name == "@" {
				return fmt.Errorf("invalid domain in related object %d", r.ID)
			}
			r.Domain = name
		}
		if r.RR != "" {
			name, err := canonicalName(r.RR, true)
			if err != nil {
				return fmt.Errorf("invalid record name in related object %d", r.ID)
			}
			r.RR = name
		}
	}
	for _, z := range m.Zones {
		if z.CategoryID != 0 && !ids["domain_category"][z.CategoryID] {
			return fmt.Errorf("zone %d references missing category", z.ID)
		}
	}
	for _, r := range m.Related {
		for _, t := range relatedTables {
			if r.Kind != t.kind {
				continue
			}
			// Manually uploaded certificates have no issuance account.
			if t.parent == "" && r.ParentID != 0 || t.parent != "" && !ids[t.parent][r.ParentID] && !(r.Kind == "cert_order" && r.ParentID == 0) {
				return fmt.Errorf("invalid parent of %s %d", r.Kind, r.ID)
			}
			if r.Kind == "cert_deploy" && !ids["cert_order"][r.OrderID] || r.Kind != "cert_deploy" && r.OrderID != 0 {
				return fmt.Errorf("invalid order reference on %s %d", r.Kind, r.ID)
			}
			if (r.Kind == "domain_alias" || r.Kind == "permission" || r.Kind == "cert_domain" || r.Kind == "cert_cname") != (r.Domain != "") || (r.RR != "" && r.Kind != "permission" && r.Kind != "cert_cname") {
				return fmt.Errorf("invalid name fields on %s %d", r.Kind, r.ID)
			}
			if r.Kind == "cert_cname" && strings.TrimSpace(r.RR) == "" {
				return fmt.Errorf("missing record name for challenge %d", r.ID)
			}
			break
		}
	}
	return nil
}
