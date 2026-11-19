package dnsmcp

import (
	"context"
	"encoding/json"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/dnsbatch"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

var extendedRecordQueryOps = []operation{{"check", "record.read"}, {"weight_list", "record.read"}}
var extendedRecordManageOps = []operation{
	{"batch_edit", "record.batch"}, {"batch_add", "record.batch"}, {"edit_by_name", "record.update"},
	{"weight_status", "record.weight"}, {"weight_update", "record.weight"},
}

func protected(r dns.DNSRecord, zone string) bool {
	return r.ReadOnly || strings.EqualFold(strings.TrimSuffix(r.Name, "."), strings.TrimSuffix(zone, ".")) &&
		(strings.EqualFold(r.Type, "NS") || strings.EqualFold(r.Type, "SOA"))
}

func stillWritable(e *core.RequestEvent, z dnsauth.Zone) bool {
	if !activeGrant(e) {
		return false
	}
	current, err := dnsauth.GetZone(e, z.ID, true)
	return err == nil && current.Provider == z.Provider && current.AccessID == z.AccessID && current.ZoneID == z.ZoneID &&
		strings.EqualFold(current.Name, z.Name)
}

type recordWrite struct {
	id     string
	action string
	input  dns.RecordInput
	value  string
}

func (w recordWrite) apply(ctx context.Context, p dns.Provider, z dnsauth.Zone) (string, error) {
	switch w.action {
	case "add":
		return p.CreateDNSRecord(ctx, z.ZoneID, w.input)
	case "update":
		return p.PatchDNSRecord(ctx, z.ZoneID, w.id, dns.RecordPatch{Content: w.input.Content, TTL: w.input.TTL})
	case "delete":
		return p.DeleteDNSRecord(ctx, z.ZoneID, w.id)
	case "group":
		return w.id, p.(dnsbatch.Groups).SetBatchGroup(ctx, z.ZoneID, w.id, w.value)
	default:
		return w.id, p.(dnsbatch.Metadata).SetBatchAttribute(ctx, z.ZoneID, w.id, w.action, w.value)
	}
}

func runRecordWrites(e *core.RequestEvent, p dns.Provider, z dnsauth.Zone, writes []recordWrite) (object, *opError) {
	if len(writes) == 0 || len(writes) > 100 {
		return nil, invalid
	}
	var last string
	for i, w := range writes {
		if !stillWritable(e, z) {
			if i == 0 {
				return nil, denied
			}
			return partial(i, len(writes), "Grant no longer active")
		}
		id, err := w.apply(e.Request.Context(), p, z)
		if err != nil {
			if i == 0 {
				return nil, upstream
			}
			return partial(i, len(writes), "Refresh provider state before retrying")
		}
		last = id
	}
	return object{"code": 0, "msg": "OK", "id": last, "completed": len(writes)}, nil
}

func recordTargets(args object, index map[string]dns.DNSRecord) ([]dns.DNSRecord, *opError) {
	var data []byte
	if raw, ok := args["records"].(string); ok {
		data = []byte(raw)
	} else {
		data, _ = json.Marshal(args["records"])
	}
	var requested []object
	if json.Unmarshal(data, &requested) != nil || len(requested) < 1 || len(requested) > 100 {
		return nil, invalid
	}
	result := make([]dns.DNSRecord, 0, len(requested))
	seen := map[string]bool{}
	for _, item := range requested {
		id := str(item, "RecordId")
		r, ok := index[id]
		if !ok || id == "" {
			return nil, missing
		}
		if seen[id] {
			return nil, invalid
		}
		seen[id] = true
		result = append(result, r)
	}
	return result, nil
}

func metadataSupports(p dns.Provider, field string) bool {
	if field == "group" {
		_, ok := p.(dnsbatch.Groups)
		return ok
	}
	m, ok := p.(dnsbatch.Metadata)
	return ok && slices.Contains(m.BatchFields(), field)
}

func writesForAttribute(p dns.Provider, z dnsauth.Zone, targets []dns.DNSRecord, field, value string) ([]recordWrite, *opError) {
	if !metadataSupports(p, field) {
		return nil, unsupported
	}
	if len(value) > 512 || value == "" && field != "remark" && field != "group" {
		return nil, invalid
	}
	out := make([]recordWrite, 0, len(targets))
	for _, r := range targets {
		if protected(r, z.Name) {
			return nil, unsupported
		}
		out = append(out, recordWrite{id: r.ID, action: field, value: value})
	}
	return out, nil
}

func legacyLine(provider, line string) string {
	switch provider {
	case "cloudflare":
		if line == "" || line == "default" {
			return "0"
		}
	case "tencentcloud":
		if line == "" || line == "default" {
			return "默认"
		}
	}
	if line == "" {
		return "default"
	}
	return line
}

func inputForRecord(z dnsauth.Zone, name, typ, value string, ttl int) (dns.RecordInput, *opError) {
	input := dns.RecordInput{Type: strings.ToUpper(typ), Name: owner(name, z.Name), Content: value, TTL: ttl}
	caps, ok := dns.ProviderCapabilities(z.Provider)
	if !ok || !caps.AllowsType(input.Type) {
		return dns.RecordInput{}, unsupported
	}
	if !inZone(input.Name, z.Name) || !caps.AllowsTTL(ttl) || value == "" || len(value) > 65535 || strings.ContainsRune(value, 0) {
		return dns.RecordInput{}, invalid
	}
	if input.Type == "A" || input.Type == "AAAA" {
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.Zone() != "" || (input.Type == "A") != ip.Is4() {
			return dns.RecordInput{}, invalid
		}
	}
	return input, nil
}

func createWrites(z dnsauth.Zone, args object, batch bool) ([]recordWrite, *opError) {
	ttl, ok := number(args, "ttl", 600, 0, math.MaxInt32)
	if !ok {
		return nil, invalid
	}
	caps, ok := dns.ProviderCapabilities(z.Provider)
	if !ok {
		return nil, unsupported
	}
	line := str(args, "line")
	if len(line) > 512 {
		return nil, invalid
	}
	// An omitted or default line delegates to the adapter's provider-specific default.
	if line == "default" {
		line = ""
	}
	if proxy, exists := args["proxy"]; exists && line == "" {
		if z.Provider != "cloudflare" {
			return nil, invalid
		}
		switch proxy {
		case true, "1", "true", float64(1):
			line = "1"
		case false, "0", "false", float64(0):
			line = "0"
		default:
			return nil, invalid
		}
	}
	remark := str(args, "remark")
	if len(remark) > 512 {
		return nil, invalid
	}
	weight, wok := number(args, "weight", 0, 0, math.MaxInt32)
	priority, pok := number(args, "mx", 1, 0, 65535)
	if !wok || !pok {
		return nil, invalid
	}
	if !caps.Line && line != "" || !caps.Weight && weight != 0 || !caps.Description && remark != "" {
		return nil, unsupported
	}

	var inputs [][2]string
	if batch {
		for _, raw := range strings.Split(strings.TrimSpace(str(args, "record")), "\n") {
			if strings.TrimSpace(raw) == "" {
				continue
			}
			pair := strings.SplitN(strings.TrimSpace(strings.ReplaceAll(raw, "\t", " ")), " ", 2)
			if len(pair) != 2 {
				return nil, invalid
			}
			inputs = append(inputs, [2]string{pair[0], strings.TrimSpace(pair[1])})
		}
	} else {
		inputs = [][2]string{{str(args, "name"), str(args, "value")}}
	}
	if len(inputs) == 0 || len(inputs) > 100 {
		return nil, invalid
	}
	out := make([]recordWrite, 0, len(inputs))
	seen := map[[3]string]bool{}
	for _, item := range inputs {
		typ := str(args, "type")
		if batch && typ == "" {
			typ = "CNAME"
			if ip, err := netip.ParseAddr(item[1]); err == nil {
				typ = "AAAA"
				if ip.Is4() {
					typ = "A"
				}
			}
		}
		input, problem := inputForRecord(z, item[0], typ, item[1], ttl)
		if problem != nil {
			return nil, problem
		}
		input.Line, input.Description = line, remark
		if _, exists := args["weight"]; exists && caps.Weight {
			input.Weight = &weight
		}
		if slices.Contains(caps.PriorityTypes, input.Type) {
			if input.Type == "MX" || args["mx"] != nil {
				input.Priority = &priority
			}
		} else if priority != 1 {
			return nil, unsupported
		}
		key := [3]string{input.Name, input.Type, input.Content}
		if seen[key] {
			return nil, invalid
		}
		seen[key] = true
		out = append(out, recordWrite{action: "add", input: input})
	}
	return out, nil
}

func editWrites(p dns.Provider, z dnsauth.Zone, grant scope, args object, targets []dns.DNSRecord) ([]recordWrite, *opError) {
	remark, remarkPresent := args["remark"].(string)
	if _, exists := args["remark"]; exists && (!remarkPresent || len(remark) > 512) {
		return nil, invalid
	}
	weight, wok := number(args, "weight", 0, 0, math.MaxInt32)
	priority, pok := number(args, "mx", 1, 0, 65535)
	if !pok || !wok {
		return nil, invalid
	}
	out := make([]recordWrite, 0, len(targets))
	for _, r := range targets {
		if protected(r, z.Name) {
			return nil, unsupported
		}
		row := recordRow(r, z)
		if name := str(args, "name"); name != "" && !strings.EqualFold(owner(name, z.Name), owner(row["Name"].(string), z.Name)) {
			return nil, unsupported
		}
		if typ := str(args, "type"); typ != "" && !strings.EqualFold(r.Type, typ) {
			return nil, unsupported
		}
		if _, exists := args["mx"]; exists && r.Type == "MX" && (r.Priority == nil || *r.Priority != priority) {
			return nil, unsupported
		}
		ttl, ok := number(args, "ttl", r.TTL, 0, math.MaxInt32)
		if !ok {
			return nil, invalid
		}
		input, problem := inputForRecord(z, r.Name, r.Type, str(args, "value"), ttl)
		if problem != nil {
			return nil, problem
		}
		out = append(out, recordWrite{action: "update", id: r.ID, input: input})
		// Validate every requested secondary attribute before any write.
		var extras []recordWrite
		if line := str(args, "line"); line != "" && legacyLine(z.Provider, line) != legacyLine(z.Provider, row["Line"].(string)) {
			if len(line) > 512 || !metadataSupports(p, "line") {
				return nil, unsupported
			}
			extras = append(extras, recordWrite{id: r.ID, action: "line", value: legacyLine(z.Provider, line)})
		}
		if remarkPresent && remark != r.Description {
			if !slices.Contains(grant.Actions, "record.remark") {
				return nil, denied
			}
			if !metadataSupports(p, "remark") {
				return nil, unsupported
			}
			extras = append(extras, recordWrite{id: r.ID, action: "remark", value: remark})
		}
		if _, given := args["weight"]; given && (r.Weight == nil && weight != 0 || r.Weight != nil && *r.Weight != weight) {
			if !slices.Contains(grant.Actions, "record.weight") {
				return nil, denied
			}
			if !metadataSupports(p, "weight") {
				return nil, unsupported
			}
			extras = append(extras, recordWrite{id: r.ID, action: "weight", value: strconv.Itoa(weight)})
		}
		out = append(out, extras...)
	}
	return out, nil
}

func mutate(e *core.RequestEvent, p dns.Provider, z dnsauth.Zone, grant scope, action string, args object) (object, *opError) {
	if action == "add" || action == "batch_add" {
		if !slices.Contains(grant.Actions, "record.add") {
			return nil, denied
		}
		changes, problem := createWrites(z, args, action == "batch_add")
		if problem != nil {
			return nil, problem
		}
		return runRecordWrites(e, p, z, changes)
	}
	records, problem := authorizedRecords(e.Request.Context(), p, z)
	if problem != nil {
		return nil, problem
	}
	index := map[string]dns.DNSRecord{}
	for _, r := range records {
		index[r.ID] = r
	}
	if action == "weight_status" || action == "weight_update" {
		return weightChange(e, p, z, action, args, index)
	}
	var targets []dns.DNSRecord
	switch action {
	case "batch", "batch_edit":
		targets, problem = recordTargets(args, index)
		if problem != nil {
			return nil, problem
		}
	case "edit_by_name":
		name, typ := owner(str(args, "name"), z.Name), strings.ToUpper(str(args, "type"))
		if !inZone(name, z.Name) || typ == "" || str(args, "value") == "" {
			return nil, invalid
		}
		for _, r := range records {
			row := recordRow(r, z)
			if strings.EqualFold(name, owner(row["Name"].(string), z.Name)) && r.Type == typ &&
				legacyLine(z.Provider, row["Line"].(string)) == legacyLine(z.Provider, "") {
				targets = append(targets, r)
			}
		}
		if len(targets) == 0 {
			return nil, missing
		}
	default:
		id := str(args, "recordid")
		if id == "" {
			return nil, invalid
		}
		r, ok := index[id]
		if !ok {
			return nil, missing
		}
		targets = []dns.DNSRecord{r}
	}
	for _, r := range targets {
		if protected(r, z.Name) {
			return nil, unsupported
		}
	}
	var writes []recordWrite
	switch action {
	case "update", "edit_by_name":
		writes, problem = editWrites(p, z, grant, args, targets)
	case "set_status", "set_remark":
		field := strings.TrimPrefix(action, "set_")
		value, present := args[field]
		if !present || value == nil {
			return nil, invalid
		}
		v := str(args, field)
		if field == "status" {
			switch v {
			case "1":
				v = "enabled"
			case "0":
				v = "disabled"
			default:
				return nil, invalid
			}
		} else if _, ok := value.(string); !ok {
			return nil, invalid
		}
		writes, problem = writesForAttribute(p, z, targets, field, v)
	case "delete":
		writes = []recordWrite{{id: targets[0].ID, action: "delete"}}
	case "batch":
		field := str(args, "batch_action")
		var v string
		switch field {
		case "open":
			field, v = "status", "enabled"
		case "pause":
			field, v = "status", "disabled"
		case "group":
			v = str(args, "groupid")
			if _, ok := args["groupid"].(string); !ok {
				return nil, invalid
			}
		case "remark":
			v = str(args, "remark")
			if _, ok := args["remark"].(string); !ok {
				return nil, invalid
			}
		case "delete":
		default:
			return nil, invalid
		}
		if !slices.Contains(grant.Actions, "record."+field) {
			return nil, denied
		}
		if field == "delete" {
			for _, r := range targets {
				writes = append(writes, recordWrite{id: r.ID, action: "delete"})
			}
		} else {
			writes, problem = writesForAttribute(p, z, targets, field, v)
		}
	case "batch_edit":
		if !slices.Contains(grant.Actions, "record.update") {
			return nil, denied
		}
		switch str(args, "edit_type") {
		case "value":
			if str(args, "type") == "" {
				return nil, invalid
			}
			writes, problem = editWrites(p, z, grant, args, targets)
		case "line":
			writes, problem = writesForAttribute(p, z, targets, "line", str(args, "line"))
		default:
			return nil, invalid
		}
	default:
		return nil, invalid
	}
	if problem != nil {
		return nil, problem
	}
	return runRecordWrites(e, p, z, writes)
}

// validate each weight target against the authorized zone, owner, type and line
// before enabling the provider rule.
func weightChange(e *core.RequestEvent, p dns.Provider, z dnsauth.Zone, action string, args object, index map[string]dns.DNSRecord) (object, *opError) {
	w, ok := p.(interface {
		SetWeightRule(context.Context, string, dns.WeightRule) error
	})
	if !ok {
		return nil, unsupported
	}
	name, typ, line := owner(str(args, "subdomain"), z.Name), strings.ToUpper(str(args, "type")), str(args, "line")
	status := str(args, "status")
	if !inZone(name, z.Name) || (status != "0" && status != "1") || line == "" || len(line) > 512 ||
		(typ != "A" && typ != "AAAA" && !(action == "weight_update" && typ == "CNAME")) {
		return nil, invalid
	}
	var writes []recordWrite
	if action == "weight_update" && status == "1" {
		weights, ok := args["weights"].(map[string]any)
		if !ok || len(weights) < 1 || len(weights) > 100 {
			return nil, invalid
		}
		if !metadataSupports(p, "weight") {
			return nil, unsupported
		}
		for id := range weights {
			r, ok := index[id]
			if !ok || !strings.EqualFold(strings.TrimSuffix(r.Name, "."), name) || r.Type != typ || r.Line != line || protected(r, z.Name) {
				return nil, missing
			}
			n, ok := number(weights, id, 0, 1, 100)
			if !ok {
				return nil, invalid
			}
			writes = append(writes, recordWrite{id: id, action: "weight", value: strconv.Itoa(n)})
		}
		slices.SortFunc(writes, func(a, b recordWrite) int { return strings.Compare(a.id, b.id) })
	}
	changedRule := typ != "CNAME"
	if changedRule {
		if !stillWritable(e, z) {
			return nil, denied
		}
		if err := w.SetWeightRule(e.Request.Context(), z.ZoneID, dns.WeightRule{Name: name, Type: typ, Line: line, Enabled: status == "1"}); err != nil {
			return nil, upstream
		}
	}
	if len(writes) == 0 {
		return object{"code": 0, "msg": "OK"}, nil
	}
	data, problem := runRecordWrites(e, p, z, writes)
	if problem != nil && changedRule {
		return nil, &opError{409, "Weight rule changed: " + problem.message}
	}
	return data, problem
}
