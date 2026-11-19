package qingcloud

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/dnsdrivers/selfhostutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type writeValue struct {
	Value  string `json:"value"`
	Status int    `json:"status"`
}
type writeGroup struct {
	Weight int          `json:"weight"`
	Values []writeValue `json:"values"`
}

func payload(r record, groups []writeGroup) (map[string]any, error) {
	z, err := dnsutil.ZoneName(r.Zone)
	if err != nil {
		return nil, err
	}
	name, err := dnsutil.RelativeName(r.Name, z)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(groups)
	if err != nil {
		return nil, err
	}
	return map[string]any{"zone_name": z + ".", "domain_name": name, "type": r.Type, "ttl": r.TTL, "mode": r.Mode, "view_id": *r.Line, "record": string(data)}, nil
}

func wireValue(kind, content string, priority *int) (string, error) {
	if content == "" {
		return "", dns.ErrInvalidDNSRequest
	}
	switch kind {
	case "MX":
		return dnsutil.MXValue(kind, content, priority, "")
	case "TXT":
		return strconv.Quote(content), nil
	default:
		return content, nil
	}
}

func (p *provider) CreateDNSRecord(ctx context.Context, zone string, in dns.RecordInput) (string, error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", err
	}
	host, err := dnsutil.RelativeName(in.Name, z)
	if err != nil {
		return "", err
	}
	if in.TTL < 60 || in.Description != "" || in.Priority != nil && in.Type != "MX" {
		return "", dns.ErrInvalidDNSRequest
	}
	line := 0
	if in.Line != "" && in.Line != "default" {
		line, err = strconv.Atoi(in.Line)
		if err != nil || line < 0 {
			return "", dns.ErrInvalidDNSRequest
		}
	}
	val, err := wireValue(in.Type, in.Content, in.Priority)
	if err != nil {
		return "", err
	}
	weight, mode := 0, 1
	if in.Weight != nil {
		if (in.Type != "A" && in.Type != "CNAME") || *in.Weight < 0 {
			return "", dns.ErrInvalidDNSRequest
		}
		weight = *in.Weight
		mode = 3
	}
	r := record{Zone: z, Name: dnsutil.FullName(host, z), Mode: mode, Line: &line, TTL: in.TTL, Type: in.Type}
	params, err := payload(r, []writeGroup{{Weight: weight, Values: []writeValue{{Value: val, Status: 1}}}})
	if err != nil {
		return "", err
	}
	params["auto_merge"] = 2
	var out struct {
		ID      int64 `json:"domain_record_id"`
		Records []struct {
			Values []struct {
				ID    int64  `json:"id"`
				Value string `json:"value"`
			} `json:"value"`
		} `json:"records"`
	}
	defer selfhostutil.LockZone("qingcloud", z)()
	if err = p.call(ctx, "POST", "/v1/record/", nil, params, &out); err != nil {
		return "", err
	}
	if out.ID <= 0 {
		return "", errResponse
	}
	var vid int64
	for _, g := range out.Records {
		for _, v := range g.Values {
			if v.Value == val && v.ID > 0 {
				if vid != 0 {
					return "", errResponse
				}
				vid = v.ID
			}
		}
	}
	if vid == 0 {
		return p.locate(ctx, z, out.ID, 0, val, &r)
	}
	return key(out.ID, vid), nil
}

type selected struct {
	record
	groupIndex, valueIndex int
}

func parseID(id string) (int64, int64, error) {
	r, v, ok := strings.Cut(id, "_")
	if !ok {
		return 0, 0, dns.ErrInvalidDNSRequest
	}
	rid, err := dnsutil.PositiveID(r)
	if err != nil {
		return 0, 0, err
	}
	vid, err := dnsutil.PositiveID(v)
	return rid, vid, err
}

func (p *provider) detail(ctx context.Context, z string, rid int64) (record, error) {
	var out struct{ Data record }
	if err := p.call(ctx, "GET", "/v1/dr_id/"+strconv.FormatInt(rid, 10), nil, nil, &out); err != nil {
		return record{}, err
	}
	if out.Data.ID != rid {
		return record{}, domain.ErrRecordNotFound
	}
	if err := out.Data.validate(z); err != nil {
		return record{}, err
	}
	return out.Data, nil
}

func (p *provider) selectValue(ctx context.Context, z string, rid, vid int64) (*selected, error) {
	r, err := p.detail(ctx, z, rid)
	if err != nil {
		return nil, err
	}
	for i, g := range r.Groups {
		for j, v := range g.Values {
			if v.ID == vid {
				return &selected{record: r, groupIndex: i, valueIndex: j}, nil
			}
		}
	}
	return nil, domain.ErrRecordNotFound
}

// RouteWize may reassign value IDs when a full set is updated.
func (p *provider) locate(ctx context.Context, z string, rid, old int64, content string, expected *record) (string, error) {
	r, err := p.detail(ctx, z, rid)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(strings.TrimSuffix(r.Name, "."), strings.TrimSuffix(expected.Name, ".")) || r.Type != expected.Type || r.TTL != expected.TTL || *r.Line != *expected.Line || r.Mode != expected.Mode {
		return "", errResponse
	}
	var matches []int64
	for _, g := range r.Groups {
		for _, v := range g.Values {
			if *v.Value == content {
				if v.ID == old {
					return key(rid, old), nil
				}
				matches = append(matches, v.ID)
			}
		}
	}
	if len(matches) != 1 {
		return "", errResponse
	}
	return key(rid, matches[0]), nil
}

func (p *provider) changeStatus(ctx context.Context, id int64, target, action string) error {
	return p.call(ctx, "POST", "/v1/change_record_status/", nil, map[string]any{"ids": []int64{id}, "target": target, "action": action}, nil)
}

func (p *provider) mutate(ctx context.Context, zone, id string, patch *dns.RecordPatch, field, value string) (string, error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", err
	}
	rid, vid, err := parseID(id)
	if err != nil {
		return "", err
	}
	defer selfhostutil.LockZone("qingcloud", z)()
	s, err := p.selectValue(ctx, z, rid, vid)
	if err != nil {
		return "", err
	}
	old := s.Groups[s.groupIndex].Values[s.valueIndex]
	next := *old.Value
	switch field {
	case "status":
		action := "enable"
		switch value {
		case "enabled", "1":
		case "disabled", "0":
			action = "stop"
		default:
			return "", dns.ErrInvalidDNSRequest
		}
		if err = p.changeStatus(ctx, vid, "value", action); err != nil {
			return "", err
		}
		return id, nil
	case "weight":
		if s.Type != "A" && s.Type != "CNAME" || len(s.Groups[s.groupIndex].Values) > 1 {
			return "", dns.ErrInvalidDNSRequest
		}
		weight, err := strconv.Atoi(value)
		if err != nil || weight < 0 {
			return "", dns.ErrInvalidDNSRequest
		}
		s.Mode = 3
		s.Groups[s.groupIndex].Weight = &weight
	case "update":
		if patch.TTL < 60 {
			return "", dns.ErrInvalidDNSRequest
		}
		if patch.TTL != s.TTL && (len(s.Groups) > 1 || len(s.Groups[0].Values) > 1) {
			return "", dns.ErrInvalidDNSRequest
		}
		d, err := row(s.record, s.Groups[s.groupIndex], old)
		if err != nil {
			return "", err
		}
		next, err = wireValue(s.Type, patch.Content, d.Priority)
		if err != nil {
			return "", err
		}
		s.TTL = patch.TTL
	case "delete":
	default:
		return "", dns.ErrInvalidDNSRequest
	}
	return p.replaceSelection(ctx, z, s, next, field == "delete")
}

func (p *provider) replaceSelection(ctx context.Context, z string, s *selected, next string, remove bool) (string, error) {
	rid := s.ID
	vid := s.Groups[s.groupIndex].Values[s.valueIndex].ID
	id := key(rid, vid)
	var groups []writeGroup
	for i, g := range s.Groups {
		// The provider does not take group status on replacement. Preserve a
		// paused group's state by refusing a rewrite that would activate it.
		if g.Status != 1 {
			return "", dns.ErrInvalidDNSRequest
		}
		wg := writeGroup{Weight: *g.Weight}
		for j, v := range g.Values {
			val := *v.Value
			if i == s.groupIndex && j == s.valueIndex {
				if remove {
					continue
				}
				val = next
			}
			wg.Values = append(wg.Values, writeValue{Value: val, Status: v.Status})
		}
		if len(wg.Values) > 0 {
			groups = append(groups, wg)
		}
	}
	if len(groups) == 0 {
		if err := p.changeStatus(ctx, rid, "record", "delete"); err != nil {
			return "", err
		}
		return id, nil
	}
	params, err := payload(s.record, groups)
	if err != nil {
		return "", err
	}
	if err = p.call(ctx, "POST", "/v1/dr_id/"+strconv.FormatInt(rid, 10), nil, params, nil); err != nil {
		return "", err
	}
	if remove {
		return id, nil
	}
	return p.locate(ctx, z, rid, vid, next, &s.record)
}

func (p *provider) PatchDNSRecord(ctx context.Context, zone, id string, patch dns.RecordPatch) (string, error) {
	return p.mutate(ctx, zone, id, &patch, "update", "")
}
func (p *provider) DeleteDNSRecord(ctx context.Context, zone, id string) (string, error) {
	return p.mutate(ctx, zone, id, nil, "delete", "")
}

func (p *provider) BatchFields() []string { return []string{"status", "weight"} }
func (p *provider) BatchAttribute(ctx context.Context, zone, id, field string) (string, error) {
	z, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", err
	}
	rid, vid, err := parseID(id)
	if err != nil {
		return "", err
	}
	s, err := p.selectValue(ctx, z, rid, vid)
	if err != nil {
		return "", err
	}
	g := s.Groups[s.groupIndex]
	v := g.Values[s.valueIndex]
	switch field {
	case "status":
		if v.Status == 1 {
			return "enabled", nil
		}
		return "disabled", nil
	case "weight":
		if s.Type == "A" || s.Type == "CNAME" {
			return strconv.Itoa(*g.Weight), nil
		}
	}
	return "", dns.ErrInvalidDNSRequest
}
func (p *provider) SetBatchAttribute(ctx context.Context, zone, id, field, value string) error {
	if field != "status" && field != "weight" {
		return dns.ErrInvalidDNSRequest
	}
	_, err := p.mutate(ctx, zone, id, nil, field, value)
	return err
}
func (p *provider) SetDNSRecordStatus(ctx context.Context, zone, id string, enabled bool) (string, error) {
	status := "disabled"
	if enabled {
		status = "enabled"
	}
	return p.mutate(ctx, zone, id, nil, "status", status)
}
