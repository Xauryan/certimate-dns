package dnsmcp

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	wire "github.com/miekg/dns"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/dnsbatch"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func owner(name, zone string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	if name == "@" {
		return zone
	}
	if name == "" {
		return ""
	}
	if strings.HasSuffix(name, ".") {
		return strings.TrimSuffix(name, ".")
	}
	if name == zone || strings.HasSuffix(name, "."+zone) {
		return name
	}
	return name + "." + zone
}

func inZone(name, zone string) bool {
	if name == "" || zone == "" || strings.ContainsAny(name, "\\;()@\"") || strings.IndexFunc(name, unicode.IsSpace) >= 0 {
		return false
	}
	_, valid := wire.IsDomainName(name)
	return valid && wire.IsSubDomain(wire.Fqdn(zone), wire.Fqdn(name))
}

func authorizedRecords(ctx context.Context, p dns.Provider, z dnsauth.Zone) ([]dns.DNSRecord, *opError) {
	rows, err := dnsbatch.Records(ctx, p, z.ZoneID)
	if err != nil {
		return nil, upstream
	}
	for _, r := range rows {
		if !inZone(r.Name, z.Name) {
			return nil, upstream
		}
	}
	return rows, nil
}

func recordRow(r dns.DNSRecord, z dnsauth.Zone) object {
	zone := strings.ToLower(strings.TrimSuffix(z.Name, "."))
	name := strings.ToLower(strings.TrimSuffix(r.Name, "."))
	if name == zone {
		name = "@"
	} else {
		name = strings.TrimSuffix(name, "."+zone)
	}
	status := r.Status
	switch strings.ToLower(status) {
	case "enable", "enabled", "active", "1", "":
		status = "1"
	case "disable", "disabled", "paused", "0":
		status = "0"
	}
	line := r.Line
	if z.Provider == "cloudflare" {
		line = "0"
		if r.Proxied {
			line = "1"
		}
		if plain, paused := strings.CutSuffix(name, "_pause"); paused {
			name, status = plain, "0"
			if name == "__root__" {
				name = "@"
			}
		}
	}
	if line == "" {
		line = "default"
	}
	return object{"RecordId": r.ID, "Domain": zone, "Name": name, "Type": r.Type, "Value": r.Content,
		"TTL": r.TTL, "Line": line, "LineName": line, "Status": status, "MX": r.Priority, "Weight": r.Weight,
		"Remark": r.Description, "UpdateTime": r.UpdatedAt, "Proxied": r.Proxied}
}

func query(e *core.RequestEvent, p dns.Provider, z dnsauth.Zone, action string, args object) (object, *opError) {
	ctx := e.Request.Context()
	offset, limit, ok := paging(args)
	if !ok {
		return nil, invalid
	}
	switch action {
	case "check":
		return recordCheck(e, p, z, args)
	case "weight_list":
		return weightList(e, p, z, args, offset, limit)
	case "groups":
		g, ok := p.(dnsbatch.Groups)
		if !ok {
			return nil, unsupported
		}
		data, err := g.BatchGroups(ctx, z.ZoneID)
		if err != nil {
			return nil, upstream
		}
		return object{"code": 0, "data": data}, nil
	case "log":
		h, ok := p.(dnsbatch.ProviderHistory)
		if !ok {
			return nil, unsupported
		}
		return providerPage(offset, limit, func(n int) (*dns.DNSPage[dnsbatch.Log], error) { return h.BatchLogs(ctx, z.ZoneID, n) }, func(row dnsbatch.Log) object {
			return object{"time": row.Time, "data": row.Action}
		})
	}
	rr := str(args, "subdomain")
	if action == "subdomain" {
		rr = str(args, "rr")
		if rr == "" {
			return nil, invalid
		}
	}
	// With no filters, seek directly to the upstream page containing the first requested row.
	if rr == "" && str(args, "keyword") == "" && str(args, "type") == "" && str(args, "value") == "" && str(args, "line") == "" && str(args, "status") == "" {
		return recordsPage(e, p, z, offset, limit)
	}
	records, problem := authorizedRecords(ctx, p, z)
	if problem != nil {
		return nil, problem
	}
	rows := []object{}
	for _, r := range records {
		row := recordRow(r, z)
		if action == "subdomain" && row["Name"] == "@" && (r.Type == "NS" || r.Type == "SOA") {
			continue
		}
		if rr != "" && !strings.EqualFold(owner(rr, z.Name), owner(row["Name"].(string), z.Name)) {
			continue
		}
		if kw := strings.ToLower(str(args, "keyword")); kw != "" && !strings.Contains(strings.ToLower(r.Name+" "+r.Content), kw) {
			continue
		}
		if t := str(args, "type"); t != "" && !strings.EqualFold(r.Type, t) {
			continue
		}
		if val := str(args, "value"); val != "" && r.Content != val {
			continue
		}
		if line := str(args, "line"); line != "" && row["Line"] != line {
			continue
		}
		if status := str(args, "status"); status != "" && row["Status"] != status {
			continue
		}
		rows = append(rows, row)
	}
	if action == "subdomain" {
		return object{"code": 0, "data": rows}, nil
	}
	return page(rows, offset, limit), nil
}

func recordsPage(e *core.RequestEvent, p dns.Provider, z dnsauth.Zone, offset, limit int) (object, *opError) {
	return providerPage(offset, limit, func(n int) (*dns.DNSPage[dns.DNSRecord], error) {
		return p.DNSRecords(e.Request.Context(), z.ZoneID, n, "")
	}, func(r dns.DNSRecord) object {
		if !inZone(r.Name, z.Name) || r.ID == "" {
			return nil
		}
		return recordRow(r, z)
	})
}

func providerPage[T any](offset, limit int, fetch func(int) (*dns.DNSPage[T], error), convert func(T) object) (object, *opError) {
	rows := []object{}
	total := -1
	for n := offset/dns.DNSPageSize + 1; ; n++ {
		result, err := fetch(n)
		if err != nil || result == nil || result.Info.Total < 0 || result.Info.Page != n || total >= 0 && total != result.Info.Total {
			return nil, upstream
		}
		total = result.Info.Total
		start := (n - 1) * dns.DNSPageSize
		if len(result.Items) != min(dns.DNSPageSize, max(0, total-start)) {
			return nil, upstream
		}
		for i, item := range result.Items {
			row := convert(item)
			if row == nil {
				return nil, upstream
			}
			if start+i >= offset && len(rows) < limit {
				rows = append(rows, row)
			}
		}
		if start+len(result.Items) >= total || len(rows) == limit {
			break
		}
	}
	return object{"total": total, "rows": rows}, nil
}

// Aliyun counts subdomains on each page. Its adapter flattens line algorithms
// within a subdomain, so regroup them before applying the legacy offset.
func weightList(e *core.RequestEvent, p dns.Provider, z dnsauth.Zone, args object, offset, limit int) (object, *opError) {
	w, ok := p.(interface {
		WeightRules(context.Context, string, int, string) (*dns.DNSPage[dns.WeightRule], error)
	})
	if !ok {
		return nil, unsupported
	}
	return providerPage(offset, limit, func(n int) (*dns.DNSPage[object], error) {
		r, err := w.WeightRules(e.Request.Context(), z.ZoneID, n, str(args, "keyword"))
		if err != nil || r == nil {
			return nil, err
		}
		out := &dns.DNSPage[object]{Info: r.Info}
		byOwner := map[[2]string]object{}
		for _, rule := range r.Items {
			if !inZone(rule.Name, z.Name) {
				return nil, dns.ErrInvalidDNSRequest
			}
			key := [2]string{rule.Name, rule.Type}
			row := byOwner[key]
			if row == nil {
				rr := recordRow(dns.DNSRecord{Name: rule.Name}, z)["Name"]
				row = object{"SubDomain": rule.Name, "rr": rr, "Type": rule.Type, "Open": rule.Enabled,
					"id": len(out.Items) + 1, "LineAlgorithms": object{"LineAlgorithm": []object{}}}
				byOwner[key] = row
				out.Items = append(out.Items, row)
			}
			if rule.Line != "" {
				lines := row["LineAlgorithms"].(object)
				lines["LineAlgorithm"] = append(lines["LineAlgorithm"].([]object), object{"Line": rule.Line, "Open": rule.Enabled})
			}
		}
		return out, nil
	}, func(row object) object { return row })
}

func partial(count, total int, reason string) (object, *opError) {
	return nil, &opError{409, fmt.Sprintf("%d of %d operations confirmed: %s", count, total, reason)}
}
