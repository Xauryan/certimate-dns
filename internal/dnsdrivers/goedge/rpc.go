// Package goedge manages records in a GoEdge NS cluster.
package goedge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/dnsdrivers/selfhostutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type provider struct {
	rpc               *selfhostutil.Client
	role, keyID, key  string
	clusterID, userID int64

	tokenMu    sync.Mutex
	token      string
	validUntil time.Time
}

// configID accepts JSON numbers from the API and decimal strings from existing forms.
func configID(v any) (int64, error) {
	b, err := json.Marshal(v)
	var n json.Number
	if err != nil || json.Unmarshal(b, &n) != nil {
		return 0, domain.ErrInvalidParams
	}
	return dnsutil.PositiveID(n.String())
}

func New(a *domain.Access) (dns.Provider, error) {
	server := dnsutil.Field(a, "serverUrl")
	rpc, err := selfhostutil.NewClientWithHTTP(server, dnsutil.HTTPClientFor(a))
	if err != nil {
		return nil, domain.ErrInvalidParams
	}
	// A cleartext HTTP node is opt-in and must resolve directly to a local
	// address. Do not resolve arbitrary hostnames to decide whether they qualify.
	endpoint, _ := url.Parse(rpc.Base)
	if endpoint.Scheme == "http" {
		allowed, _ := a.Config["allowInsecureConnections"].(bool)
		host := endpoint.Hostname()
		ip, _ := netip.ParseAddr(host)
		ip = ip.Unmap()
		if !allowed || !(strings.EqualFold(host, "localhost") || ip.IsPrivate() || ip.IsLoopback()) {
			return nil, domain.ErrInvalidParams
		}
	}
	rpc.ApplyTLSConfig(a)
	p := &provider{rpc: rpc, role: dnsutil.Field(a, "apiRole"), keyID: dnsutil.Field(a, "accessKeyId"), key: dnsutil.Field(a, "accessKey")}
	if p.key == "" || p.keyID == "" || (p.role != "admin" && p.role != "user") {
		return nil, domain.ErrInvalidParams
	}
	p.clusterID, err = configID(a.Config["nsClusterId"])
	if err != nil {
		return nil, domain.ErrInvalidParams
	}
	if raw := a.Config["userId"]; raw != nil && raw != "" {
		p.userID, err = configID(raw)
		if err != nil || p.role != "admin" {
			return nil, domain.ErrInvalidParams
		}
	}
	return p, nil
}

func (p *provider) post(ctx context.Context, path, token string, payload, out any) error {
	header := http.Header{}
	if token != "" {
		header.Set("X-Edge-Access-Token", token)
	}
	var envelope struct {
		Code int
		Data json.RawMessage
	}
	if err := p.rpc.Call(ctx, http.MethodPost, path, nil, payload, header, &envelope); err != nil {
		return err
	}
	if envelope.Code != 200 {
		return selfhostutil.ErrProvider
	}
	if out != nil && (len(envelope.Data) == 0 || string(envelope.Data) == "null" || json.Unmarshal(envelope.Data, out) != nil) {
		return selfhostutil.ErrProvider
	}
	return nil
}

func (p *provider) accessToken(ctx context.Context) (string, error) {
	p.tokenMu.Lock()
	defer p.tokenMu.Unlock()
	if p.token != "" && time.Now().Before(p.validUntil) {
		return p.token, nil
	}
	var result struct {
		Token     string
		ExpiresAt json.Number
	}
	auth := map[string]string{"type": p.role, "accessKeyId": p.keyID, "accessKey": p.key}
	if err := p.post(ctx, "/APIAccessTokenService/getAPIAccessToken", "", auth, &result); err != nil {
		return "", err
	}
	if result.Token == "" {
		return "", selfhostutil.ErrProvider
	}
	exp, _ := result.ExpiresAt.Int64()
	p.token = result.Token
	p.validUntil = time.Unix(exp, 0).Add(-5 * time.Second)
	return p.token, nil
}

func (p *provider) call(ctx context.Context, path string, payload, out any) error {
	token, err := p.accessToken(ctx)
	if err != nil {
		return err
	}
	return p.post(ctx, path, token, payload, out)
}

type scopeID struct{ ID json.Number }
type nsDomain struct {
	ID           json.Number
	Name, Status string
	NSCluster    *scopeID
	UserID       json.Number
	User         *scopeID
}

func (p *provider) zoneQuery() map[string]any {
	q := map[string]any{"nsClusterId": p.clusterID}
	if p.userID > 0 {
		q["userId"] = p.userID
	}
	return q
}

func (p *provider) count(ctx context.Context, path string, q map[string]any) (int, error) {
	var r struct{ Count json.Number }
	if err := p.call(ctx, path, q, &r); err != nil {
		return 0, err
	}
	// Protobuf JSON omits a zero-valued count.
	if r.Count == "" {
		return 0, nil
	}
	n, err := r.Count.Int64()
	if err != nil || n < 0 || int64(int(n)) != n {
		return 0, selfhostutil.ErrProvider
	}
	return int(n), nil
}

func (p *provider) listZones(ctx context.Context, q map[string]any) ([]nsDomain, error) {
	var r struct{ NSDomains []nsDomain }
	err := p.call(ctx, "/NSDomainService/listNSDomains", q, &r)
	return r.NSDomains, err
}

func (p *provider) Zones(ctx context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	if !dnsutil.ValidPage(page) {
		return nil, dns.ErrInvalidDNSRequest
	}
	q := p.zoneQuery()
	total, err := p.count(ctx, "/NSDomainService/countAllNSDomains", q)
	if err != nil {
		return nil, err
	}
	q["offset"], q["size"] = (page-1)*dns.DNSPageSize, dns.DNSPageSize
	rows, err := p.listZones(ctx, q)
	if err != nil {
		return nil, err
	}
	if !selfhostutil.CompletePage(page, total, len(rows)) {
		return nil, selfhostutil.ErrProvider
	}
	result := dnsutil.Page[dns.Zone](page, total)
	for _, z := range rows {
		if !p.inScope(z) {
			return nil, selfhostutil.ErrProvider
		}
		name, err := dnsutil.ZoneName(z.Name)
		if err != nil {
			return nil, selfhostutil.ErrProvider
		}
		if _, err := dnsutil.PositiveID(z.ID.String()); err != nil {
			return nil, selfhostutil.ErrProvider
		}
		result.Items = append(result.Items, dns.Zone{ID: z.ID.String(), Name: name, Status: z.Status})
	}
	return result, nil
}

// Some API versions omit cluster or user information in findNSDomain.
// Prove membership via the same scoped inventory used to enumerate zones then.
func (p *provider) zone(ctx context.Context, id string) (*nsDomain, error) {
	n, err := dnsutil.PositiveID(id)
	if err != nil {
		return nil, err
	}
	var r struct{ NSDomain *nsDomain }
	if err := p.call(ctx, "/NSDomainService/findNSDomain", map[string]int64{"nsDomainId": n}, &r); err != nil {
		return nil, err
	}
	z := r.NSDomain
	if z == nil || z.ID.String() != id {
		return nil, domain.ErrRecordNotFound
	}
	z.Name, err = dnsutil.ZoneName(z.Name)
	if err != nil {
		return nil, selfhostutil.ErrProvider
	}
	clusterKnown := z.NSCluster != nil && z.NSCluster.ID != ""
	if clusterKnown {
		cluster, err := z.NSCluster.ID.Int64()
		if err != nil || cluster != p.clusterID {
			return nil, domain.ErrRecordNotFound
		}
	}
	user := z.UserID
	if user == "" && z.User != nil {
		user = z.User.ID
	}
	if p.userID > 0 && user != "" {
		uid, err := user.Int64()
		if err != nil || uid != p.userID {
			return nil, domain.ErrRecordNotFound
		}
	}
	if clusterKnown && (p.userID == 0 || user != "") {
		return z, nil
	}
	q := p.zoneQuery()
	q["keyword"] = z.Name
	const size = 100
	q["size"] = size
	prev := ""
	for offset := 0; ; offset += size {
		q["offset"] = offset
		rows, err := p.listZones(ctx, q)
		if err != nil {
			return nil, err
		}
		for _, candidate := range rows {
			if candidate.ID == z.ID && strings.EqualFold(candidate.Name, z.Name) && p.inScope(candidate) {
				return z, nil
			}
		}
		if len(rows) < size {
			return nil, domain.ErrRecordNotFound
		}
		last := rows[len(rows)-1].ID.String()
		if last == prev {
			return nil, selfhostutil.ErrProvider
		}
		prev = last
	}
}

func (p *provider) inScope(z nsDomain) bool {
	if z.NSCluster != nil && z.NSCluster.ID != "" {
		n, err := z.NSCluster.ID.Int64()
		if err != nil || n != p.clusterID {
			return false
		}
	}
	user := z.UserID
	if user == "" && z.User != nil {
		user = z.User.ID
	}
	if user != "" && p.userID != 0 {
		n, err := user.Int64()
		return err == nil && n == p.userID
	}
	return true
}
func (p *provider) CreateZone(ctx context.Context, name string) (*dns.Zone, error) {
	name, err := dnsutil.ZoneName(name)
	if err != nil {
		return nil, err
	}
	q := p.zoneQuery()
	q["name"] = name
	var result struct{ NSDomainID json.Number }
	if err := p.call(ctx, "/NSDomainService/createNSDomain", q, &result); err != nil {
		return nil, err
	}
	if _, err := dnsutil.PositiveID(result.NSDomainID.String()); err != nil {
		return nil, selfhostutil.ErrProvider
	}
	return &dns.Zone{ID: result.NSDomainID.String(), Name: name}, nil
}
func (p *provider) ZoneDetails(ctx context.Context, id string) (*dns.ZoneDetails, error) {
	z, err := p.zone(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &dns.ZoneDetails{Name: z.Name, Status: z.Status, MinTTL: 1, Lines: []dns.RecordLine{{ID: "default", Name: "default"}}}
	known := map[string]bool{"default": true}
	for _, method := range []string{"findAllDefaultWorldRegionRoutes", "findAllDefaultChinaProvinceRoutes", "findAllDefaultISPRoutes", "findAllAgentNSRoutes", "findAllNSRoutes"} {
		var result struct{ NSRoutes []route }
		if err := p.call(ctx, "/NSRouteService/"+method, struct{}{}, &result); err != nil {
			return nil, err
		}
		for _, r := range result.NSRoutes {
			if r.Code == "" || known[r.Code] {
				continue
			}
			if r.NSDomain != nil && r.NSDomain.ID != "" && r.NSDomain.ID != z.ID {
				continue
			}
			if !p.inScope(nsDomain{NSCluster: r.NSCluster, UserID: r.UserID}) {
				continue
			}
			known[r.Code] = true
			name := r.Name
			if name == "" {
				name = r.Code
			}
			out.Lines = append(out.Lines, dns.RecordLine{ID: r.Code, Name: name, Parent: r.Parent})
		}
	}
	for i := range out.Lines {
		line := &out.Lines[i]
		if line.Parent != "" {
			continue
		}
		candidate := line.ID
		for {
			at := strings.LastIndexByte(candidate, ':')
			if at < 0 {
				break
			}
			candidate = candidate[:at]
			if known[candidate] {
				line.Parent = candidate
				break
			}
		}
	}
	return out, nil
}
