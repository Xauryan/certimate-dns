package cloudflare

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// AutomationRecord returns the logical owner, including when DNSMgr's reversible
// pause convention moved the physical record. An absent record is (nil, nil)
// only after confirming that the account still has access to the zone.
func (c *Client) AutomationRecord(ctx context.Context, zone, id string) (*DNSRecord, error) {
	if !dnsID.MatchString(zone) || !dnsID.MatchString(id) {
		return nil, ErrInvalidDNSRequest
	}
	z, err := c.ZoneDetails(ctx, zone)
	if err != nil {
		return nil, err
	}
	var result dnsResult[DNSRecord]
	resp, err := c.rc.R().SetContext(ctx).SetResult(&result).Get("/zones/" + zone + "/dns_records/" + id)
	if err != nil {
		return nil, errors.New("Cloudflare record lookup failed")
	}
	if resp.StatusCode() == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode() != http.StatusOK || !result.Success || result.Result.ID != id {
		return nil, errors.New("Cloudflare record unavailable")
	}
	r := result.Result
	owner, err := relativeOwner(r.Name, z.Name)
	if err != nil {
		return nil, err
	}
	r.Status = "enabled"
	if strings.HasSuffix(owner, "_pause") {
		r.Name, err = pauseOwner(r.Name, z.Name, r.Type, "enabled")
		if err != nil {
			return nil, err
		}
		r.Status = "disabled"
	}
	return &r, nil
}

// PatchDNSRecordProxy applies the proxy mode and the new value in one provider request.
func (c *Client) PatchDNSRecordProxy(ctx context.Context, zone, id string, changes RecordPatch, proxied bool) (string, error) {
	if !dnsID.MatchString(zone) || !dnsID.MatchString(id) {
		return "", ErrInvalidDNSRequest
	}
	return writeRecord(ctx, c, http.MethodPatch, "/zones/"+zone+"/dns_records/"+id, struct {
		RecordPatch
		Proxied bool `json:"proxied"`
	}{changes, proxied})
}
