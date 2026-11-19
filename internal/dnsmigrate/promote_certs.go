package dnsmigrate

import (
	"database/sql"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/pocketbase/dbx"
)

// Certificate promotions attach legacy IDs to operator-selected native objects.
// No promotion reads credentials, starts an issuance or runs a deployment.
func (p *planner) planCertPromotion(b Promotion, source Item, _ bool) (promotionWork, error) {
	r := source.details.(Related)
	if b.Role != "" && !(r.Kind == "cert_order" && b.Role == "certificate") {
		return promotionWork{Conflict: "unexpected role on certificate association"}, nil
	}
	switch r.Kind {
	case "cert_account":
		return p.verifyCertificateAccount(b.TargetID, r)
	case "cert_order":
		return p.verifyCertificateOrder(b, r)
	case "cert_domain":
		id, ok := p.promotionTarget("cert_order", r.ParentID)
		if !ok || id != b.TargetID {
			return promotionWork{Conflict: "certificate name must reference its explicitly mapped parent order or certificate"}, nil
		}
		// The parent verification checks the complete set of legacy DNS identities.
		return promotionWork{}, nil
	case "cert_deploy":
		account, aok := p.promotionTarget("cert_account", r.ParentID)
		order, ook := p.promotionTarget("cert_order", r.OrderID)
		src, sok := p.sourceItem("cert_account", r.ParentID)
		if !aok || !ook || !sok || src.details.(Related).State != 1 {
			return promotionWork{Conflict: "map the deployment account and order before linking a deployment"}, nil
		}
		orderItem, ok := p.sourceItem("cert_order", r.OrderID)
		if !ok || orderItem.details.(Related).ParentID == 0 {
			return promotionWork{Conflict: "deployment requires a native certificate order"}, nil
		}
		for _, chosen := range p.bindings.Promotions {
			if chosen.Kind == "cert_order" && chosen.LegacyID == r.OrderID && chosen.Role == "certificate" {
				return promotionWork{Conflict: "deployment requires a native certificate order"}, nil
			}
		}
		return p.verifyCertLink(`SELECT t.id FROM dns_cert_deploy t
			JOIN workflow w ON w.id=t.workflow_id AND w.hasContent=1
			JOIN access a ON a.id=t.access_id AND a.deleted=''
			JOIN dns_cert_orders o ON o.id=t.order_id AND o.state<>'deleted'
			WHERE t.id={:id} AND t.order_id={:order} AND t.access_id={:account}
			AND (SELECT count(*) FROM json_each(w.graphContent,'$.nodes') n WHERE n.value->>'$.id'=t.node_id) = 1
			AND EXISTS(SELECT 1 FROM json_each(w.graphContent,'$.nodes') n WHERE n.value->>'$.id'=t.node_id
				AND n.value->>'$.type'='bizDeploy' AND n.value->>'$.data.config.providerAccessId'=a.id
				AND (n.value->>'$.data.config.provider'=a.provider OR substr(n.value->>'$.data.config.provider',1,length(a.provider)+1)=a.provider||'-'))`,
			dbx.Params{"id": b.TargetID, "account": account, "order": order}, "deployment account, order or published destination node differs")
	case "cert_cname":
		zone, ok := p.sourceItem("domain", r.ParentID)
		if !ok || zone.AccountID == "" || zone.Action == "conflict" {
			return promotionWork{Conflict: "map the challenge destination zone before linking its CNAME"}, nil
		}
		sourceZone, ok := p.cnameSourceZone(r.Domain)
		if !ok {
			return promotionWork{Conflict: "challenge source zone is ambiguous or not mapped"}, nil
		}
		return p.verifyCertLink(`SELECT c.id FROM dns_cert_cnames c JOIN dnsZone t ON c.target_zone_id=t.id AND c.target_name=t.name
			JOIN dnsZone s ON c.source_zone_id=s.id AND c.source_name=s.name WHERE c.id={:id} AND t.id={:target}
			AND ({:source}='' OR s.id={:source})
			AND c.rr={:rr} AND c.domain={:domain} AND (c.domain=s.name OR substr(c.domain,-length(s.name)-1)='.'||s.name)`,
			dbx.Params{"id": b.TargetID, "source": sourceZone, "target": zone.Target, "rr": r.RR, "domain": r.Domain}, "CNAME source domain, destination zone or record name differs")
	}
	return promotionWork{Conflict: "unsupported certificate reference"}, nil
}

// DNSMgr only records the destination zone ID. When the source is in the
// inventory, require the local source identity of its most specific zone.
func (p *planner) cnameSourceZone(domain string) (string, bool) {
	length := 0
	target := ""
	matched := false
	for _, z := range p.manifest.Zones {
		if len(z.Name) < length || (domain != z.Name && !strings.HasSuffix(domain, "."+z.Name)) {
			continue
		}
		if matched && len(z.Name) == length {
			target = ""
			continue
		}
		matched = true
		length = len(z.Name)
		target = ""
		zone, ok := p.sourceItem("domain", z.ID)
		if ok && zone.AccountID != "" && zone.Action != "conflict" {
			target = zone.Target
		}
	}
	return target, !matched || target != ""
}

func (p *planner) verifyCertLink(query string, params dbx.Params, reason string) (promotionWork, error) {
	_, found, err := p.scalar(query, params)
	if err == nil && !found {
		return promotionWork{Conflict: reason}, nil
	}
	return promotionWork{}, err
}

// Certificate-interface accounts record their legacy type in addition to the
// native provider and issuer/deployer role.
func (p *planner) verifyCertificateAccount(target string, r Related) (promotionWork, error) {
	if r.Provider == "" || (r.State != 0 && r.State != 1) {
		return promotionWork{Conflict: "export the certificate account provider and role before binding it"}, nil
	}
	native := certProviderAliases[r.Provider]
	if native == "" {
		native = r.Provider
	}
	acme := slices.Contains([]string{"letsencrypt", "zerossl", "google", "litessl", "customacme"}, r.Provider)
	issuer := acme || slices.Contains([]string{"tencent", "aliyun", "ucloud"}, r.Provider)
	if r.State == 0 && !issuer || r.State == 1 && acme {
		return promotionWork{Conflict: "source provider is incompatible with the certificate account role"}, nil
	}
	reserve := ""
	if acme {
		reserve = "ca"
	}
	return p.verifyCertLink(`SELECT a.id FROM access a LEFT JOIN dns_cert_account_meta m ON m.access_id=a.id
		WHERE a.id={:id} AND a.deleted='' AND (a.provider={:native} OR ({:native}='letsencrypt' AND a.provider='letsencryptstaging'))
		AND ((m.legacy_type={:type} AND m.deploy={:role}) OR (m.access_id IS NULL AND {:role}=0))
		AND a.reserve={:reserve}`, dbx.Params{"id": target, "type": r.Provider, "role": r.State, "native": native, "reserve": reserve},
		"certificate account missing or legacy type or issuer/deployer role differs")
}

var certProviderAliases = map[string]string{
	"google": "googletrustservices", "customacme": "acmeca", "tencent": "tencentcloud",
	"btpanel": "baotapanel", "btwin": "baotapanelgo", "btwaf": "baotawaf", "opanel": "1panel",
	"acepanel": "ratpanel", "synology": "synologydsm", "proxmox": "proxmoxve",
	"huawei": "huaweicloud", "doge": "dogecloud", "baidu": "baiducloud", "huoshan": "volcengine",
	"west": "westcn", "ctyun": "ctcccloud", "s3storage": "s3",
}

func (p *planner) verifyCertificateOrder(b Promotion, r Related) (promotionWork, error) {
	names := map[string]bool{}
	for _, d := range p.manifest.Related {
		if d.Kind == "cert_domain" && d.ParentID == r.ID {
			names[d.Domain] = true
		}
	}
	if len(names) == 0 {
		return promotionWork{Conflict: "order requires exported DNS identifiers"}, nil
	}
	var account string
	if r.ParentID != 0 {
		var exists bool
		account, exists = p.promotionTarget("cert_account", r.ParentID)
		src, ok := p.sourceItem("cert_account", r.ParentID)
		if !exists || !ok || src.details.(Related).State != 0 {
			return promotionWork{Conflict: "map the original issuance account before linking its order"}, nil
		}
	}
	if r.ParentID == 0 || b.Role == "certificate" {
		if account != "" {
			// Query only the issuance node identity and credential reference from
			// the immutable workflow run. Never load the full graph or key.
			link, err := p.verifyCertLink(`SELECT c.id FROM certificate c
				JOIN workflow_run w ON w.id=c.workflowRunRef AND w.workflowRef=c.workflowRef
				JOIN access a ON a.id={:account} AND a.deleted=''
				WHERE c.id={:id} AND c.deleted='' AND c.source='request'
				AND (WITH RECURSIVE nodes(node) AS (
					SELECT value FROM json_each(w.graph,'$.nodes')
					UNION ALL SELECT child.value FROM nodes JOIN json_each(nodes.node,'$.blocks') child
				) SELECT count(*)=1 AND max(node->>'$.type'='bizApply' AND node->>'$.data.config.caProviderAccessId'=a.id)
				  FROM nodes WHERE node->>'$.id'=c.workflowNodeId)`, dbx.Params{"id": b.TargetID, "account": account},
				"workflow certificate issuance node or CA access differs")
			if err != nil || link.Conflict != "" {
				return link, err
			}
		}
		return p.verifyCertificateNames(b.TargetID, names, account == "")
	}
	var order struct {
		Domain      string `db:"domain"`
		Certificate string `db:"certificate_id"`
	}
	err := p.db.NewQuery(`SELECT o.domain,o.certificate_id FROM dns_cert_orders o JOIN access a ON a.id=o.access_id AND a.provider=o.provider AND a.deleted=''
		WHERE o.id={:id} AND o.access_id={:account} AND o.state<>'deleted'`).Bind(dbx.Params{"id": b.TargetID, "account": account}).WithContext(p.ctx).One(&order)
	if errors.Is(err, sql.ErrNoRows) {
		return promotionWork{Conflict: "order missing or issuer account differs"}, nil
	}
	if err != nil {
		return promotionWork{}, err
	}
	if !names[strings.TrimSuffix(strings.ToLower(order.Domain), ".")] {
		return promotionWork{Conflict: "order DNS identity differs"}, nil
	}
	if order.Certificate != "" {
		return p.verifyCertificateNames(order.Certificate, names, false)
	}
	if len(names) != 1 {
		return promotionWork{Conflict: "single-name native order does not cover the exported DNS names"}, nil
	}
	return promotionWork{}, nil
}

func (p *planner) verifyCertificateNames(target string, names map[string]bool, uploaded bool) (promotionWork, error) {
	var c struct {
		SANs string `db:"subjectAltNames"`
		CN   string `db:"subjectName"`
	}
	err := p.db.NewQuery(`SELECT subjectAltNames,subjectName FROM certificate WHERE id={:id} AND deleted='' AND ({:upload}=0 OR source='upload')`).Bind(dbx.Params{"id": target, "upload": uploaded}).WithContext(p.ctx).One(&c)
	if errors.Is(err, sql.ErrNoRows) {
		return promotionWork{Conflict: "certificate missing, deleted or not an uploaded certificate"}, nil
	}
	if err != nil {
		return promotionWork{}, err
	}
	got := map[string]bool{}
	for _, n := range strings.Split(c.SANs, ";") {
		if n != "" {
			got[strings.TrimSuffix(strings.ToLower(n), ".")] = true
		}
	}
	if c.CN != "" {
		n := strings.TrimSuffix(strings.ToLower(c.CN), ".")
		if len(got) == 0 {
			got[n] = true
		} else if !got[n] {
			return promotionWork{Conflict: "certificate common name differs from the DNS identifiers"}, nil
		}
	}
	if !maps.Equal(got, names) {
		return promotionWork{Conflict: "certificate DNS identifiers differ from the complete exported set"}, nil
	}
	return promotionWork{}, nil
}
