// Package henet manages hosted DNS records through the Hurricane Electric control panel.
package henet

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/html"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

var failure = errors.New("HE DNS returned an unexpected page; refresh the zone before retrying a change")

type provider struct {
	base, username, password string
	client                   *http.Client
}

func New(a *domain.Access) (dns.Provider, error) {
	user, pass := dnsutil.Field(a, "username"), dnsutil.Field(a, "password")
	if user == "" || pass == "" {
		return nil, domain.ErrInvalidParams
	}
	return &provider{"https://dns.he.net/", user, pass, dnsutil.HTTPClientFor(a)}, nil
}

func (p *provider) page(ctx context.Context, c *http.Client, path string, form url.Values) (*html.Node, error) {
	method, body := http.MethodGet, ""
	if form != nil {
		method, body = http.MethodPost, form.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, p.base+path, strings.NewReader(body))
	if err != nil {
		return nil, failure
	}
	req.Header.Set("Referer", p.base)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	data, err := dnsutil.ReadResponse(c, req)
	if err != nil {
		return nil, err
	}
	doc, err := html.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, failure
	}
	return doc, nil
}

func attr(n *html.Node, k string) string {
	for _, a := range n.Attr {
		if a.Key == k {
			return a.Val
		}
	}
	return ""
}
func nodeText(n *html.Node) string {
	var b strings.Builder
	for el := range n.Descendants() {
		if el.Type == html.TextNode && el.Parent.Data != "script" && el.Parent.Data != "style" {
			b.WriteString(el.Data)
		}
	}
	return strings.TrimSpace(b.String())
}

func parseZones(doc *html.Node) ([]dns.Zone, error) {
	var zones []dns.Zone
	index := make(map[string]string)
	domainsTable := false
	for n := range doc.Descendants() {
		if n.Type != html.ElementNode {
			continue
		}
		if n.Data == "table" && attr(n, "id") == "domains_table" {
			domainsTable = true
		}
		var id, name string
		switch {
		case strings.Contains(strings.ToLower(attr(n, "onclick")), "delete_dom(this)"):
			id, name = attr(n, "value"), attr(n, "name")
		case n.Data == "a":
			u, err := url.Parse(attr(n, "href"))
			if err != nil {
				continue
			}
			id, name = u.Query().Get("hosted_dns_zoneid"), nodeText(n)
			// Icon-only edit links share the zone URL with a labelled link.
			if id == "" || name == "" || !strings.Contains(name, ".") {
				continue
			}
		default:
			continue
		}
		if _, err := dnsutil.PositiveID(id); err != nil {
			return nil, failure
		}
		name, err := dnsutil.ZoneName(name)
		if err != nil {
			return nil, failure
		}
		if old, ok := index[id]; ok {
			if old != name {
				return nil, failure
			}
			continue
		}
		index[id] = name
		zones = append(zones, dns.Zone{ID: id, Name: name, Status: "active"})
	}
	if !domainsTable && len(zones) == 0 {
		return nil, failure
	}
	return zones, nil
}

// A fresh cookie jar per operation keeps concurrent logins and user sessions independent.
func (p *provider) session(ctx context.Context) (*http.Client, []dns.Zone, error) {
	client := *p.client
	client.Jar, _ = cookiejar.New(nil)
	if _, err := p.page(ctx, &client, "", nil); err != nil {
		return nil, nil, err
	}
	doc, err := p.page(ctx, &client, "", url.Values{"email": {p.username}, "pass": {p.password}})
	if err != nil {
		return nil, nil, err
	}
	zones, err := parseZones(doc)
	return &client, zones, err
}
func (p *provider) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	_, zones, err := p.session(ctx)
	if err != nil {
		return nil, err
	}
	return dnsutil.SlicePage(zones, page)
}
func (p *provider) zone(ctx context.Context, id string) (*http.Client, dns.Zone, error) {
	if _, err := dnsutil.PositiveID(id); err != nil {
		return nil, dns.Zone{}, err
	}
	client, zones, err := p.session(ctx)
	if err != nil {
		return nil, dns.Zone{}, err
	}
	for _, z := range zones {
		if z.ID == id {
			return client, z, nil
		}
	}
	return nil, dns.Zone{}, domain.ErrRecordNotFound
}
func (p *provider) ZoneDetails(ctx context.Context, id string) (*dns.ZoneDetails, error) {
	_, z, err := p.zone(ctx, id)
	if err != nil {
		return nil, err
	}
	return &dns.ZoneDetails{Name: z.Name, MinTTL: 300, Lines: []dns.RecordLine{{ID: "default", Name: "Default"}}}, nil
}
func editable(typ string) bool {
	switch typ {
	case "A", "AAAA", "CNAME", "ALIAS", "TXT", "MX", "NS", "CAA", "SRV", "PTR":
		return true
	}
	return false
}

func recordRow(row *html.Node, zone dns.Zone) (dns.DNSRecord, error) {
	var cells []string
	for n := range row.ChildNodes() {
		if n.Type == html.ElementNode && n.Data == "td" {
			cells = append(cells, nodeText(n))
		}
	}
	// The first two cells are hidden HE identifiers. Keep empty priority cells
	// in position, including when the TXT value contains repeated spaces.
	if len(cells) < 7 || cells[0] != zone.ID || cells[1] != attr(row, "id") {
		return dns.DNSRecord{}, failure
	}
	if _, err := dnsutil.PositiveID(cells[1]); err != nil {
		return dns.DNSRecord{}, failure
	}
	host, err := dnsutil.RelativeName(cells[2], zone.Name)
	if err != nil || cells[2] == "@" {
		return dns.DNSRecord{}, failure
	}
	typ := strings.ToUpper(cells[3])
	ttl, err := strconv.Atoi(cells[4])
	if typ == "" || err != nil || ttl < 0 || cells[6] == "" {
		return dns.DNSRecord{}, failure
	}
	var priority *int
	if typ == "MX" {
		v, err := strconv.Atoi(cells[5])
		if err != nil || v < 0 || v > 65535 {
			return dns.DNSRecord{}, failure
		}
		priority = &v
	}
	content := cells[6]
	if typ == "TXT" {
		content = unquote(content)
	}
	status := "enabled"
	if slices.Contains(strings.Fields(attr(row, "class")), "disabled") {
		status = "disabled"
	}
	// Dynamic records also carry an update key managed by HE's separate form.
	dynamic := len(cells) > 7 && cells[7] == "1"
	return dns.DNSRecord{ID: cells[1], Name: dnsutil.FullName(host, zone.Name), Type: typ, Content: content, TTL: ttl, Priority: priority, Status: status, Line: "default", ReadOnly: dynamic || !editable(typ)}, nil
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func parseRecords(doc *html.Node, z dns.Zone) ([]dns.DNSRecord, error) {
	var records []dns.DNSRecord
	ids := make(map[string]bool)
	zoneConfirmed := false
	for n := range doc.Descendants() {
		if n.Type != html.ElementNode {
			continue
		}
		if n.Data == "input" && attr(n, "name") == "hosted_dns_zoneid" && attr(n, "value") == z.ID {
			zoneConfirmed = true
		}
		if n.Data != "tr" || !slices.Contains(strings.Fields(attr(n, "class")), "dns_tr") {
			continue
		}
		row, err := recordRow(n, z)
		if err != nil || ids[row.ID] {
			return nil, failure
		}
		ids[row.ID] = true
		records = append(records, row)
	}
	if len(records) == 0 && !zoneConfirmed {
		return nil, failure
	}
	return records, nil
}
func (p *provider) records(ctx context.Context, id string) (*http.Client, dns.Zone, []dns.DNSRecord, error) {
	c, z, err := p.zone(ctx, id)
	if err != nil {
		return nil, z, nil, err
	}
	q := url.Values{"hosted_dns_zoneid": {id}, "menu": {"edit_zone"}, "hosted_dns_editzone": {""}}
	doc, err := p.page(ctx, c, "index.cgi?"+q.Encode(), nil)
	if err != nil {
		return nil, z, nil, err
	}
	rows, err := parseRecords(doc, z)
	return c, z, rows, err
}
func (p *provider) DNSRecords(ctx context.Context, id string, page int, name string) (*dns.DNSPage[dns.DNSRecord], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	_, z, rows, err := p.records(ctx, id)
	if err != nil {
		return nil, err
	}
	if name != "" {
		host, e := dnsutil.RelativeName(name, z.Name)
		if e != nil {
			return nil, e
		}
		want := dnsutil.FullName(host, z.Name)
		rows = slices.DeleteFunc(rows, func(r dns.DNSRecord) bool { return r.Name != want })
	}
	return dnsutil.SlicePage(rows, page)
}
func form(z dns.Zone, id, name, typ, content string, ttl int, priority *int) url.Values {
	prio := ""
	if priority != nil {
		prio = strconv.Itoa(*priority)
	}
	if typ == "TXT" {
		content = unquote(content)
	}
	return url.Values{"account": {""}, "menu": {"edit_zone"}, "hosted_dns_zoneid": {z.ID}, "hosted_dns_recordid": {id}, "hosted_dns_editzone": {"1"}, "Type": {typ}, "Name": {name}, "Content": {content}, "TTL": {strconv.Itoa(ttl)}, "Priority": {prio}}
}
func (p *provider) mutate(ctx context.Context, c *http.Client, params url.Values, expected string) (*html.Node, error) {
	doc, err := p.page(ctx, c, "index.cgi", params)
	if err != nil {
		return nil, err
	}
	for n := range doc.Descendants() {
		if n.Type == html.ElementNode && attr(n, "id") == "dns_status" && strings.HasPrefix(nodeText(n), expected) {
			return doc, nil
		}
	}
	return nil, failure
}
func (p *provider) CreateDNSRecord(ctx context.Context, zone string, in dns.RecordInput) (string, error) {
	if !editable(in.Type) || (in.Line != "" && in.Line != "default") || in.TTL < 300 || in.Content == "" || in.Weight != nil || in.Description != "" || (in.Priority != nil && (in.Type != "MX" || *in.Priority < 0 || *in.Priority > 65535)) {
		return "", dns.ErrInvalidDNSRequest
	}
	c, z, rows, err := p.records(ctx, zone)
	if err != nil {
		return "", err
	}
	host, err := dnsutil.RelativeName(in.Name, z.Name)
	if err != nil {
		return "", err
	}
	name := dnsutil.FullName(host, z.Name)
	var priority *int
	if in.Type == "MX" {
		v := 1
		if in.Priority != nil {
			v = *in.Priority
		}
		priority = &v
	}
	params := form(z, "", name, in.Type, in.Content, in.TTL, priority)
	params.Set("hosted_dns_editrecord", "Submit")
	doc, err := p.mutate(ctx, c, params, "Successfully added new record")
	if err != nil {
		return "", err
	}
	updated, err := parseRecords(doc, z)
	if err != nil {
		return "", err
	}
	existing := make(map[string]bool, len(rows))
	for _, r := range rows {
		existing[r.ID] = true
	}
	id := ""
	for _, r := range updated {
		if !existing[r.ID] && r.Name == name && r.Type == in.Type && r.Content == params.Get("Content") {
			if id != "" {
				return "", failure
			}
			id = r.ID
		}
	}
	if id == "" {
		return "", failure
	}
	return id, nil
}
func (p *provider) current(ctx context.Context, zone, id string) (*http.Client, dns.Zone, dns.DNSRecord, error) {
	if _, err := dnsutil.PositiveID(id); err != nil {
		return nil, dns.Zone{}, dns.DNSRecord{}, err
	}
	c, z, rows, err := p.records(ctx, zone)
	if err != nil {
		return nil, z, dns.DNSRecord{}, err
	}
	for _, r := range rows {
		if r.ID == id {
			if r.ReadOnly {
				return nil, z, r, dns.ErrInvalidDNSRequest
			}
			return c, z, r, nil
		}
	}
	return nil, z, dns.DNSRecord{}, domain.ErrRecordNotFound
}
func (p *provider) PatchDNSRecord(ctx context.Context, zone, id string, in dns.RecordPatch) (string, error) {
	if in.TTL < 300 || in.Content == "" {
		return "", dns.ErrInvalidDNSRequest
	}
	c, z, r, err := p.current(ctx, zone, id)
	if err != nil {
		return "", err
	}
	params := form(z, id, r.Name, r.Type, in.Content, in.TTL, r.Priority)
	params.Set("hosted_dns_editrecord", "Update")
	if _, err := p.mutate(ctx, c, params, "Successfully updated record"); err != nil {
		return "", err
	}
	return id, nil
}
func (p *provider) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	c, z, _, err := p.current(ctx, zone, id)
	if err != nil {
		return "", err
	}
	params := url.Values{"menu": {"edit_zone"}, "hosted_dns_zoneid": {z.ID}, "hosted_dns_recordid": {id}, "hosted_dns_editzone": {"1"}, "hosted_dns_delrecord": {"1"}, "hosted_dns_delconfirm": {"delete"}}
	if _, err := p.mutate(ctx, c, params, "Successfully removed record"); err != nil {
		return "", err
	}
	return id, nil
}
