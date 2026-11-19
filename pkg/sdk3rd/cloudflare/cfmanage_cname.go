package cloudflare

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

type tunnelDNS struct {
	path, name, target string
}

func (c *Client) tunnelDNS(ctx context.Context, zone, account, tunnel, name string) (tunnelDNS, error) {
	zoneName, owner, err := c.zoneWithAccount(ctx, zone)
	if err != nil {
		return tunnelDNS{}, err
	}
	if owner.ID != account || (name != zoneName && !strings.HasSuffix(name, "."+zoneName)) {
		return tunnelDNS{}, ErrInvalidDNSRequest
	}
	return tunnelDNS{"/zones/" + zone + "/dns_records", name, tunnel + ".cfargotunnel.com"}, nil
}

func (d tunnelDNS) read(ctx context.Context, c *Client) (*DNSRecord, error) {
	data, err := pageResult[DNSRecord](ctx, c, d.path, 1, map[string]string{"name": d.name})
	if err != nil {
		return nil, err
	}
	if len(data.Items) == 0 && data.Info.Total == 0 {
		return nil, nil
	}
	if len(data.Items) != 1 || data.Info.Total > 1 {
		return nil, ErrConfigChanged
	}
	rec := data.Items[0]
	if !dnsID.MatchString(rec.ID) || !strings.EqualFold(strings.TrimSuffix(rec.Name, "."), d.name) {
		return nil, ErrConfigChanged
	}
	return &rec, nil
}

func (d tunnelDNS) matches(record *DNSRecord) bool {
	return record != nil && record.Type == "CNAME" && strings.EqualFold(strings.TrimSuffix(record.Content, "."), d.target)
}

// sync edits only the exact name in the verified zone. A CNAME for another
// application or tunnel is never silently repointed or deleted.
func (d tunnelDNS) sync(ctx context.Context, c *Client, remove bool) error {
	record, err := d.read(ctx, c)
	if err != nil {
		return err
	}
	path, method := d.path, http.MethodPost
	var body any = map[string]any{"type": "CNAME", "name": d.name, "content": d.target, "proxied": true, "ttl": 1}
	switch {
	case remove:
		if !d.matches(record) {
			return nil
		}
		path += "/" + record.ID
		method, body = http.MethodDelete, nil
	case record == nil:
	case !d.matches(record):
		return ErrConfigChanged
	case record.Proxied:
		return nil
	default:
		method = http.MethodPatch
		path += "/" + record.ID
		body = map[string]bool{"proxied": true}
	}
	_, err = getResult[struct{}](ctx, c, method, path, body)
	if err != nil {
		// A dropped response can follow a successful change.
		current, readErr := d.read(ctx, c)
		if readErr != nil {
			return errors.New("could not verify the tunnel CNAME after its update")
		}
		if (remove && !d.matches(current)) || (!remove && d.matches(current) && current.Proxied) {
			return nil
		}
	}
	return err
}
