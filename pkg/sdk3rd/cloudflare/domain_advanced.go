package cloudflare

import (
	"context"
	"strings"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func (c *Client) ZoneDetails(ctx context.Context, zone string) (*dns.ZoneDetails, error) {
	if !dnsID.MatchString(zone) {
		return nil, ErrInvalidDNSRequest
	}
	type details struct {
		Zone
		Plan struct {
			Name string `json:"name"`
		} `json:"plan"`
		Nameservers []string `json:"name_servers"`
	}
	r, err := dnsRequest[details](ctx, c, "GET", "/zones/"+zone, nil, nil)
	if err != nil {
		return nil, err
	}
	if r.Result.ID != zone || r.Result.Name == "" {
		return nil, ErrInvalidDNSRequest
	}
	return &dns.ZoneDetails{Name: r.Result.Name, Status: r.Result.Status, Plan: r.Result.Plan.Name, Nameservers: r.Result.Nameservers, Lines: []dns.RecordLine{{ID: "0", Name: "DNS only"}, {ID: "1", Name: "Proxied"}}}, nil
}

type recordSettings struct {
	DNSRecord
	Comment   string `json:"comment"`
	Proxiable bool   `json:"proxiable"`
}

func (c *Client) recordSettings(ctx context.Context, zone, id string) (*recordSettings, error) {
	if !dnsID.MatchString(zone) || !dnsID.MatchString(id) {
		return nil, ErrInvalidDNSRequest
	}
	r, err := dnsRequest[recordSettings](ctx, c, "GET", "/zones/"+zone+"/dns_records/"+id, nil, nil)
	if err != nil {
		return nil, err
	}
	if r.Result.ID != id {
		return nil, ErrInvalidDNSRequest
	}
	return &r.Result, nil
}
func (c *Client) BatchFields() []string { return []string{"status", "line", "remark"} }
func (c *Client) BatchAttribute(ctx context.Context, zone, id, field string) (string, error) {
	record, err := c.recordSettings(ctx, zone, id)
	if err != nil {
		return "", err
	}
	switch field {
	case "remark":
		return record.Comment, nil
	case "line":
		if record.Proxied {
			return "1", nil
		}
		return "0", nil
	case "status":
		d, err := c.ZoneDetails(ctx, zone)
		if err != nil {
			return "", err
		}
		label, err := relativeOwner(record.Name, d.Name)
		if err != nil {
			return "", err
		}
		if strings.HasSuffix(label, "_pause") {
			return "disabled", nil
		}
		return "enabled", nil
	}
	return "", ErrInvalidDNSRequest
}
func relativeOwner(name, zone string) (string, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	if name == zone {
		return "@", nil
	}
	if label, ok := strings.CutSuffix(name, "."+zone); ok && label != "" {
		return label, nil
	}
	return "", ErrInvalidDNSRequest
}
func pauseOwner(name, zone, typ, state string) (string, error) {
	label, err := relativeOwner(name, zone)
	if err != nil {
		return "", err
	}
	if state != "enabled" && state != "disabled" {
		return "", ErrInvalidDNSRequest
	}
	if typ == "SOA" || (label == "@" && typ == "NS") {
		return "", ErrInvalidDNSRequest
	}
	paused := strings.HasSuffix(label, "_pause")
	if paused == (state == "disabled") {
		return name, nil
	}
	if paused {
		label = strings.TrimSuffix(label, "_pause")
		if label == "__root__" {
			return zone, nil
		}
		if label == "" {
			return "", ErrInvalidDNSRequest
		}
	} else {
		if label == "@" {
			label = "__root__"
		} else if label == "__root__" {
			return "", ErrInvalidDNSRequest
		}
		label += "_pause"
	}
	owner := label + "." + zone
	if len(owner) > 253 {
		return "", ErrInvalidDNSRequest
	}
	for _, s := range strings.Split(owner, ".") {
		if len(s) > 63 {
			return "", ErrInvalidDNSRequest
		}
	}
	return owner, nil
}
func (c *Client) SetBatchAttribute(ctx context.Context, zone, id, field, value string) error {
	if !dnsID.MatchString(zone) || !dnsID.MatchString(id) {
		return ErrInvalidDNSRequest
	}
	record, err := c.writableRecord(ctx, zone, id)
	if err != nil {
		return err
	}
	var body map[string]any
	switch field {
	case "remark":
		body = map[string]any{"comment": value}
	case "line":
		if (value != "0" && value != "1") || (value == "1" && record.Type != "A" && record.Type != "AAAA" && record.Type != "CNAME") {
			return ErrInvalidDNSRequest
		}
		body = map[string]any{"proxied": value == "1"}
	case "status":
		d, err := c.ZoneDetails(ctx, zone)
		if err != nil {
			return err
		}
		name, err := pauseOwner(record.Name, d.Name, record.Type, value)
		if err != nil {
			return err
		}
		if record.Name == name {
			return nil
		}
		body = map[string]any{"name": name}
	default:
		return ErrInvalidDNSRequest
	}
	result, err := writeRecord(ctx, c, "PATCH", "/zones/"+zone+"/dns_records/"+id, body)
	if err == nil && result != id {
		return ErrInvalidDNSRequest
	}
	return err
}
