package dnscatalog

import (
	"context"
	"slices"
	"strings"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

type Certificate struct {
	ID              string `db:"id" json:"id"`
	SubjectName     string `db:"subjectName" json:"subjectName"`
	SubjectAltNames string `db:"subjectAltNames" json:"subjectAltNames"`
	Expires         string `db:"validityNotAfter" json:"expires"`
	WorkflowID      string `db:"workflowRef" json:"workflowId"`
}

type Link struct {
	ID   string `db:"id" json:"id"`
	Name string `db:"name" json:"name"`
}

type Detail struct {
	*Domain
	Certificates []Certificate `json:"certificates"`
	Workflows    []Link        `json:"workflows"`
	Tasks        []Link        `json:"tasks"`
}

func includesZone(names, zone string) bool {
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	for item := range strings.SplitSeq(names, ";") {
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(item)), ".")
		if name == zone || strings.HasSuffix(name, "."+zone) {
			return true
		}
	}
	return false
}

func detail(ctx context.Context, app core.App, id string) (*Detail, error) {
	z, err := lookup(app, id, "")
	if err != nil {
		return nil, err
	}
	h := &Detail{Domain: z, Certificates: []Certificate{}, Workflows: []Link{}, Tasks: []Link{}}
	params := dbx.Params{"name": strings.ToLower(z.Name)}
	var certs []Certificate
	err = app.DB().NewQuery(`SELECT id,subjectName,subjectAltNames,validityNotAfter,workflowRef FROM certificate
WHERE deleted='' AND (instr(lower(subjectName),{:name})>0 OR instr(lower(subjectAltNames),{:name})>0)
ORDER BY validityNotAfter DESC,id`).Bind(params).WithContext(ctx).All(&certs)
	if err != nil {
		return nil, err
	}
	producers := map[string]bool{}
	for _, c := range certs {
		if includesZone(c.SubjectName, z.Name) || includesZone(c.SubjectAltNames, z.Name) {
			h.Certificates = append(h.Certificates, c)
			producers[c.WorkflowID] = true
		}
	}

	// Project only node domains and access IDs. A workflow graph can contain
	// private keys, email addresses and provider configuration.
	var rows []struct {
		ID      string `db:"id"`
		Name    string `db:"name"`
		Domains string `db:"domains"`
		Access  string `db:"access"`
	}
	err = app.DB().NewQuery(`WITH graphs AS (
		SELECT id,name,graphContent AS graph FROM workflow WHERE hasContent
		UNION ALL SELECT id,name,graphDraft FROM workflow WHERE hasDraft)
	SELECT g.id,g.name,
		coalesce(json_extract(g.graph,n.path||'.data.config.domains'),'') AS domains,
		coalesce(nullif(json_extract(g.graph,n.path||'.data.config.dnsAccountId'),''),
		         json_extract(g.graph,n.path||'.data.config.providerAccessId'),'') AS access
	FROM graphs g,json_tree(g.graph) n WHERE n.key='type' AND n.atom='bizApply'`).WithContext(ctx).All(&rows)
	if err != nil {
		return nil, err
	}
	links := map[string]string{}
	for _, r := range rows {
		if (r.Access == "" || r.Access == z.AccessID) && includesZone(r.Domains, z.Name) {
			links[r.ID] = r.Name
		}
	}
	delete(producers, "")
	for id := range producers {
		var name string
		err := app.DB().NewQuery("SELECT coalesce(max(name),'') FROM workflow WHERE id={:id}").Bind(dbx.Params{"id": id}).WithContext(ctx).Row(&name)
		if err != nil {
			return nil, err
		}
		if name != "" {
			links[id] = name
		}
	}
	for id, name := range links {
		h.Workflows = append(h.Workflows, Link{ID: id, Name: name})
	}
	slices.SortFunc(h.Workflows, func(a, b Link) int {
		if a.Name == b.Name {
			return strings.Compare(a.ID, b.ID)
		}
		return strings.Compare(a.Name, b.Name)
	})
	// A database upgraded just to the catalog milestone can have no task table yet.
	var available int
	if err := app.DB().NewQuery("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='dns_automation_tasks'").WithContext(ctx).Row(&available); err != nil {
		return nil, err
	}
	if available != 0 {
		err = app.DB().NewQuery(`SELECT id,coalesce(json_extract(config,'$.name'),'') AS name FROM dns_automation_tasks
			WHERE state<>'archived' AND json_extract(config,'$.target.accountId')={:account}
			AND json_extract(config,'$.target.zoneId')={:zone} ORDER BY name,id`).Bind(dbx.Params{"account": z.AccessID, "zone": z.ZoneID}).WithContext(ctx).All(&h.Tasks)
		if err != nil {
			return nil, err
		}
	}
	return h, nil
}
