package ddnsfleet

import (
	"database/sql"
	"encoding/json"
	"errors"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

const (
	maxReportBytes = 128 << 10
	onlineWindow   = 15 * time.Minute
)

type Interface struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	IPv4 []string `json:"ipv4"`
	IPv6 []string `json:"ipv6"`
}

type report struct {
	Hostname   string      `json:"hostname"`
	Interfaces []Interface `json:"interfaces"`
}

func validateReport(r *report) bool {
	if !validText(r.Hostname, 253) || len(r.Interfaces) > 128 {
		return false
	}
	if r.Interfaces == nil {
		r.Interfaces = []Interface{}
	}
	seen := make(map[string]bool, len(r.Interfaces))
	for i := range r.Interfaces {
		iface := &r.Interfaces[i]
		if !validText(iface.Name, 128) || seen[iface.Name] || len(iface.MAC) > 64 {
			return false
		}
		seen[iface.Name] = true
		if iface.MAC != "" {
			mac, err := net.ParseMAC(iface.MAC)
			if err != nil {
				return false
			}
			iface.MAC = mac.String()
		}
		var ok bool
		iface.IPv4, ok = validateAddresses(iface.IPv4, true)
		if !ok {
			return false
		}
		iface.IPv6, ok = validateAddresses(iface.IPv6, false)
		if !ok {
			return false
		}
	}
	slices.SortFunc(r.Interfaces, func(a, b Interface) int { return strings.Compare(a.Name, b.Name) })
	return true
}

func validateAddresses(raw []string, ipv4 bool) ([]string, bool) {
	if len(raw) > 128 {
		return nil, false
	}
	ips := make([]netip.Addr, 0, len(raw))
	for _, value := range raw {
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.Zone() != "" || ip.Is4() != ipv4 || ip.Is4In6() ||
			!ip.IsGlobalUnicast() {
			return nil, false
		}
		ips = append(ips, ip)
	}
	slices.SortFunc(ips, netip.Addr.Compare)
	ips = slices.Compact(ips)
	addresses := make([]string, len(ips))
	for i, ip := range ips {
		addresses[i] = ip.String()
	}
	return addresses, true
}

func (s *Service) handleReport(e *core.RequestEvent) error {
	e.Response.Header().Set("Cache-Control", "no-store")
	auth := e.Request.Header.Values("Authorization")
	if len(auth) != 1 {
		return e.UnauthorizedError("Invalid DDNS device token.", nil)
	}
	scheme, token, ok := strings.Cut(auth[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || !validToken(token) {
		return e.UnauthorizedError("Invalid DDNS device token.", nil)
	}
	hash := hashToken(token)
	query := dbx.Params{"token_hash": hash}
	var nodeID string
	err := e.App.DB().Select("id").From("ddns_nodes").
		Where(dbx.HashExp{"token_hash": hash, "enabled": true}).WithContext(e.Request.Context()).Row(&nodeID)
	if errors.Is(err, sql.ErrNoRows) {
		return e.UnauthorizedError("Invalid DDNS device token.", nil)
	}
	if err != nil {
		return e.InternalServerError("Could not authorize DDNS device.", nil)
	}
	content, _, err := mime.ParseMediaType(e.Request.Header.Get("Content-Type"))
	if err != nil || content != "application/json" {
		return e.Error(http.StatusUnsupportedMediaType, "DDNS reports must be JSON.", nil)
	}
	var snapshot report
	if err := decodeBody(e, &snapshot); err != nil {
		return err
	}
	if !validateReport(&snapshot) {
		return e.BadRequestError("Invalid DDNS interface report.", nil)
	}
	interfaces, err := json.Marshal(snapshot.Interfaces)
	if err != nil {
		return e.InternalServerError("Could not encode DDNS report.", nil)
	}
	query["id"] = nodeID
	query["hostname"] = snapshot.Hostname
	query["interfaces"] = string(interfaces)
	query["seen_at"] = s.now().Unix()
	// Recheck the current credential immediately before persistence so a report
	// admitted before a concurrent rotation or removal cannot update the node.
	update, err := e.App.DB().NewQuery(`UPDATE ddns_nodes
		SET hostname={:hostname}, interfaces={:interfaces}, seen_at={:seen_at}, report_required=0
		WHERE id={:id} AND token_hash={:token_hash} AND enabled=1`).Bind(query).WithContext(e.Request.Context()).Execute()
	if err != nil {
		return e.InternalServerError("Could not save DDNS report.", nil)
	}
	changed, err := update.RowsAffected()
	if err != nil {
		return e.InternalServerError("Could not save DDNS report.", nil)
	}
	if changed == 0 {
		return e.UnauthorizedError("Invalid DDNS device token.", nil)
	}
	return e.NoContent(http.StatusNoContent)
}
