package dnsoptimize

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	"golang.org/x/net/idna"
)

type Target struct {
	Provider string `json:"provider"`
	Access   string `json:"access"`
	Zone     string `json:"zone"`
}

type Spec struct {
	Name         string `json:"name"`
	Source       string `json:"source"`
	CDN          string `json:"cdn"`
	Family       string `json:"family"`
	SourceLine   string `json:"sourceLine"`
	TargetLine   string `json:"targetLine"`
	TTL          int    `json:"ttl"`
	Ranks        []int  `json:"ranks"`
	ReplaceCNAME bool   `json:"replaceCname"`
}

func (s Spec) feed() Feed { return Feed{s.Source, s.CDN, s.Family} }
func (s Spec) recordType() string {
	if s.Family == "v4" {
		return "A"
	}
	return "AAAA"
}

var providerLines = map[string]map[string]string{
	"aliyun":       {"DEF": "default", "CT": "telecom", "CU": "unicom", "CM": "mobile"},
	"tencentcloud": {"DEF": "0", "CT": "10=0", "CU": "10=1", "CM": "10=3"},
	"baiducloud":   {"DEF": "default", "CT": "ct", "CU": "cnc", "CM": "cmnet"},
	"volcengine":   {"DEF": "default", "CT": "telecom", "CU": "unicom", "CM": "mobile"},
	"westcn":       {"DEF": "", "CT": "LTEL", "CU": "LCNC", "CM": "LMOB"},
	"dnsla":        {"DEF": "", "CT": "84613316902921216", "CU": "84613316923892736", "CM": "84613316953252864"},
	"jdcloud":      {"DEF": "-1", "CT": "1", "CU": "2", "CM": "3"},
	"bt":           {"DEF": "0", "CT": "285344768", "CU": "285345792", "CM": "285346816"},
	"qingcloud":    {"DEF": "0", "CT": "2", "CU": "3", "CM": "4"},
	"huaweicloud":  {"DEF": "default_view", "CT": "Dianxin", "CU": "Liantong", "CM": "Yidong"},
	"cloudflare":   {"DEF": "0"}, "aws": {"DEF": ""}, "namesilo": {"DEF": "default"}, "henet": {"DEF": "default"},
	"powerdns": {"DEF": "default"}, "spaceship": {"DEF": "default"}, "aliyunesa": {"DEF": "0"}, "tencenteo": {"DEF": "Default"},
	"dnsmgr": {"DEF": "default"}, "goedge": {"DEF": "default"},
}

var dnsPodNames = map[string]string{"默认": "0", "电信": "10=0", "联通": "10=1", "移动": "10=3"}

func hostname(name string) (string, error) {
	n, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), "."))
	if err != nil || len(n) > 253 || n == "" {
		return "", domain.ErrInvalidParams
	}
	for _, label := range strings.Split(n, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", domain.ErrInvalidParams
		}
	}
	return n, nil
}
func normalize(t Target, zoneName string, s Spec) (Spec, error) {
	zone, err := hostname(zoneName)
	_, supportedLine := providerLines[t.Provider][s.TargetLine]
	if err != nil || t.Zone == "" || t.Access == "" || providerLines[t.Provider] == nil || !s.feed().valid() || !slices.Contains(lines, s.SourceLine) || !supportedLine || s.TTL < 1 || s.TTL > 604800 || len(s.Ranks) < 1 || len(s.Ranks) > maxRanks {
		return s, domain.ErrInvalidParams
	}
	switch t.Provider {
	case "cloudflare", "aliyunesa":
		if s.TTL != 1 && (s.TTL < 30 || s.TTL > 86400) {
			return s, domain.ErrInvalidParams
		}
	case "tencenteo":
		if s.TTL < 60 || s.TTL > 86400 {
			return s, domain.ErrInvalidParams
		}
	case "spaceship":
		if s.TTL < 60 || s.TTL > 3600 {
			return s, domain.ErrInvalidParams
		}
	case "henet", "bt":
		if s.TTL < 300 {
			return s, domain.ErrInvalidParams
		}
	}
	wildcard := strings.HasPrefix(s.Name, "*.")
	name, err := hostname(strings.TrimPrefix(s.Name, "*."))
	if err != nil || (name != zone && !strings.HasSuffix(name, "."+zone)) {
		return s, domain.NewError(400, "enter a fully qualified name in the selected zone")
	}
	if wildcard {
		name = "*." + name
	}
	if len(name) > 253 {
		return s, domain.ErrInvalidParams
	}
	s.Name = name
	s.Ranks = slices.Clone(s.Ranks)
	sort.Ints(s.Ranks)
	for i, r := range s.Ranks {
		if r < 1 || r > maxRanks || i > 0 && r == s.Ranks[i-1] {
			return s, domain.ErrInvalidParams
		}
	}
	return s, nil
}

type Change struct {
	Action      string `json:"action"`
	ID          string `json:"id,omitempty"`
	Type        string `json:"type"`
	Before      string `json:"before,omitempty"`
	After       string `json:"after,omitempty"`
	PreviousTTL int    `json:"previousTtl,omitempty"`
}
type Plan struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Line    string   `json:"line"`
	TTL     int      `json:"ttl"`
	Desired []string `json:"desired"`
	Changes []Change `json:"changes"`
	Digest  string   `json:"digest"`
}

func matchingRecords(ctx context.Context, p dns.Provider, t Target, s Spec) ([]dns.DNSRecord, error) {
	name, line, kind := s.Name, providerLines[t.Provider][s.TargetLine], s.recordType()
	var result []dns.DNSRecord
	total := -1
	read := 0
	seen := map[string]bool{}
	for n := 1; n <= 25; n++ {
		page, err := p.DNSRecords(ctx, t.Zone, n, name)
		if err != nil || page == nil {
			return nil, errors.New("could not read DNS records for the selected zone")
		}
		if total == -1 {
			total = page.Info.Total
		}
		if page.Info.Page != n || total < 0 || total > 25*dns.DNSPageSize || total != page.Info.Total {
			return nil, errors.New("DNS record listing changed or exceeds the preview limit")
		}
		for _, r := range page.Items {
			if r.ID == "" || seen[r.ID] {
				return nil, errors.New("DNS record listing contains missing or repeated IDs")
			}
			seen[r.ID] = true
			if !strings.EqualFold(strings.TrimSuffix(r.Name, "."), name) || (r.Type != kind && r.Type != "CNAME") {
				continue
			}
			if (t.Provider == "cloudflare" || t.Provider == "aliyunesa") && r.Proxied {
				return nil, errors.New("owner has a proxied DNS record")
			}
			switch t.Provider {
			case "tencenteo":
				if r.Line == "" {
					r.Line = "Default"
				}
			case "tencentcloud":
				if id, ok := dnsPodNames[strings.TrimPrefix(r.Line, "N.")]; ok {
					r.Line = id
				}
			case "dnsla":
				if r.Line == "0" || r.Line == "default" {
					r.Line = ""
				}
			}
			if !strings.EqualFold(r.Line, line) {
				continue
			}
			if r.ReadOnly || r.Proxied || slices.Contains([]string{"disable", "disabled", "pause", "paused", "inactive", "stop", "stopped", "off"}, strings.ToLower(r.Status)) {
				return nil, errors.New("the selected line contains a protected, disabled or proxied record")
			}
			if r.Type == "CNAME" && !s.ReplaceCNAME {
				return nil, domain.NewError(409, "a CNAME occupies the selected DNS line")
			}
			result = append(result, r)
		}
		read += len(page.Items)
		if read == total {
			sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
			return result, nil
		}
		if len(page.Items) == 0 || read > total {
			break
		}
	}
	return nil, errors.New("incomplete DNS record listing")
}
func buildPlan(t Target, s Spec, feed candidates, records []dns.DNSRecord) (Plan, error) {
	plan := Plan{Name: s.Name, Type: s.recordType(), Line: providerLines[t.Provider][s.TargetLine], TTL: s.TTL, Changes: []Change{}}
	needed := map[string]bool{}
	addresses := feed[s.SourceLine]
	for _, rank := range s.Ranks {
		if rank > len(addresses) {
			return Plan{}, domain.NewError(409, "a selected rank is missing from the carrier feed")
		}
		ip := addresses[rank-1]
		plan.Desired = append(plan.Desired, ip)
		needed[ip] = true
	}
	if t.Provider == "huaweicloud" {
		// Huawei stores all selected answers for the owner, family and line in one RRset.
		var set *dns.DNSRecord
		for _, r := range records {
			if r.Type == "CNAME" {
				plan.Changes = append(plan.Changes, Change{Action: "delete", ID: r.ID, Type: r.Type, Before: r.Content, PreviousTTL: r.TTL})
				continue
			}
			if set != nil {
				return Plan{}, errors.New("multiple address sets occupy the selected Huawei DNS line")
			}
			set = &r
		}
		values := slices.Clone(plan.Desired)
		sort.Strings(values)
		op := Change{Action: "create", Type: plan.Type, After: strings.Join(values, "\n")}
		if set != nil {
			existing := strings.Fields(set.Content)
			sort.Strings(existing)
			if set.TTL == s.TTL && slices.Equal(existing, values) {
				return digestPlan(t, s, records, plan)
			}
			op.Action = "update"
			op.ID, op.Before, op.PreviousTTL = set.ID, set.Content, set.TTL
		}
		plan.Changes = append(plan.Changes, op)
		return digestPlan(t, s, records, plan)
	}
	if (t.Provider == "powerdns" || t.Provider == "aws") && len(records) > 1 {
		for _, r := range records {
			if r.Type == plan.Type && r.TTL != s.TTL {
				return Plan{}, domain.NewError(409, "the shared address set TTL must match the existing records")
			}
		}
	}
	var reusable []dns.DNSRecord
	for _, r := range records {
		op := Change{ID: r.ID, Type: r.Type, Before: r.Content, PreviousTTL: r.TTL}
		if r.Type == "CNAME" {
			op.Action = "delete"
			plan.Changes = append(plan.Changes, op)
			continue
		}
		addr, err := netip.ParseAddr(r.Content)
		if err == nil && needed[addr.String()] {
			delete(needed, addr.String())
			if r.TTL != s.TTL {
				op.Action = "update"
				op.After = addr.String()
				plan.Changes = append(plan.Changes, op)
			}
			continue
		}
		reusable = append(reusable, r)
	}
	for _, ip := range plan.Desired {
		if !needed[ip] {
			continue
		}
		op := Change{Action: "create", Type: plan.Type, After: ip}
		if len(reusable) > 0 {
			old := reusable[0]
			reusable = reusable[1:]
			op.Action = "update"
			op.ID = old.ID
			op.Before = old.Content
			op.PreviousTTL = old.TTL
		}
		plan.Changes = append(plan.Changes, op)
	}
	for _, r := range reusable {
		plan.Changes = append(plan.Changes, Change{Action: "delete", ID: r.ID, Type: r.Type, Before: r.Content, PreviousTTL: r.TTL})
	}
	return digestPlan(t, s, records, plan)
}

func digestPlan(t Target, s Spec, records []dns.DNSRecord, plan Plan) (Plan, error) {
	data, err := json.Marshal([]any{t, s, records, plan})
	if err != nil {
		return Plan{}, err
	}
	digest := sha256.Sum256(data)
	plan.Digest = hex.EncodeToString(digest[:])
	return plan, nil
}

type addressSets interface {
	SetRankedAddresses(context.Context, string, string, dns.RecordInput, []string) (string, error)
}

func applyPlan(ctx context.Context, p dns.Provider, t Target, s Spec, plan Plan) error {
	setWriter, isSetWriter := p.(addressSets)
	if t.Provider == "huaweicloud" && !isSetWriter {
		return errors.New("ranked address sets are unavailable for this account")
	}
	for _, op := range plan.Changes {
		if err := ctx.Err(); err != nil {
			return err
		}
		var err error
		switch {
		case t.Provider == "huaweicloud" && (op.Action == "create" || op.Action == "update"):
			_, err = setWriter.SetRankedAddresses(ctx, t.Zone, op.ID, dns.RecordInput{Type: op.Type, Name: plan.Name, TTL: plan.TTL, Line: plan.Line}, strings.Fields(op.After))
		case op.Action == "create":
			_, err = p.CreateDNSRecord(ctx, t.Zone, dns.RecordInput{Type: op.Type, Name: plan.Name, Content: op.After, TTL: plan.TTL, Line: plan.Line})
		case op.Action == "update":
			_, err = p.PatchDNSRecord(ctx, t.Zone, op.ID, dns.RecordPatch{Content: op.After, TTL: plan.TTL})
		case op.Action == "delete":
			_, err = p.DeleteDNSRecord(ctx, t.Zone, op.ID)
		default:
			return errors.New("invalid DNS operation")
		}
		if err != nil {
			return errors.New("DNS write was not confirmed; inspect the latest DNS records and preview again")
		}
	}
	if len(plan.Changes) == 0 {
		return nil
	}
	actual, err := matchingRecords(ctx, p, t, s)
	if err != nil {
		return err
	}
	if t.Provider == "huaweicloud" && len(actual) == 1 {
		set := actual[0]
		actual = nil
		for _, value := range strings.Fields(set.Content) {
			r := set
			r.Content = value
			actual = append(actual, r)
		}
	}
	if len(actual) != len(plan.Desired) {
		return errors.New("DNS write completed but the record count could not be verified")
	}
	remaining := map[string]bool{}
	for _, ip := range plan.Desired {
		remaining[ip] = true
	}
	for _, r := range actual {
		addr, err := netip.ParseAddr(r.Content)
		if err != nil || !remaining[addr.String()] || r.Type != plan.Type || r.TTL != plan.TTL {
			return errors.New("DNS write completed but the values could not be verified")
		}
		delete(remaining, addr.String())
	}
	return nil
}
