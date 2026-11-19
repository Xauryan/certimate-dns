package dnscert

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/certimate-go/certimate/internal/dnscatalog"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

// A provider record can satisfy multiple live orders. The last holder cleans
// it only when its create receipt and its current provider snapshot agree.
type challengeRecord struct {
	ID         string `db:"id"`
	LocalZone  string `db:"local_zone"`
	Provider   string `db:"provider"`
	AccessID   string `db:"access_id"`
	RemoteZone string `db:"remote_zone"`
	ZoneName   string `db:"zone_name"`
	Name       string `db:"name"`
	Type       string `db:"type"`
	Value      string `db:"value"`
	State      string `db:"state"`
	RecordID   string `db:"record_id"`
	Snapshot   string `db:"snapshot"`
}

var recordLabel = regexp.MustCompile(`^[a-z0-9_-]{1,63}$`)

func dnsName(s string) string {
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

func validRecordName(name string) bool {
	if len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !recordLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func within(name, suffix string) bool { return name == suffix || strings.HasSuffix(name, "."+suffix) }

func normalizeChallenge(c Challenge, domain, zone string) (Challenge, error) {
	c.Name = dnsName(c.Name)
	if !validRecordName(c.Name) || !within(domain, zone) || !within(c.Name, zone) {
		return c, errInput
	}
	// A CA can validate a child host at the parent's DCV label.
	_, parent, _ := strings.Cut(c.Name, ".")
	if !within(c.Name, domain) && !(strings.HasPrefix(c.Name, "_") && parent != "" && within(domain, parent)) {
		return c, errInput
	}
	if c.Type == "CNAME" {
		c.Value = dnsName(c.Value)
		if !validRecordName(c.Value) || !strings.Contains(c.Value, ".") {
			return c, errInput
		}
	}
	return c, nil
}

type challengeGuardKey struct{}

// WithChallengeZoneGuard rechecks the caller's write permission on each DNS
// zone immediately before changing references or calling a DNS provider.
func WithChallengeZoneGuard(ctx context.Context, guard func(context.Context, string) error) context.Context {
	return context.WithValue(ctx, challengeGuardKey{}, guard)
}

func authorizeChallengeZone(ctx context.Context, zone string) error {
	if guard, ok := ctx.Value(challengeGuardKey{}).(func(context.Context, string) error); ok {
		if guard == nil {
			return errConflict
		}
		return guard(ctx, zone)
	}
	return ctx.Err()
}

func (r challengeRecord) authorize(ctx context.Context, app core.App) error {
	if err := authorizeChallengeZone(ctx, r.LocalZone); err != nil {
		return err
	}
	z, err := dnscatalog.Lookup(app, r.LocalZone)
	if err != nil {
		return err
	}
	if z.AccessID != r.AccessID || z.Provider != r.Provider || z.ZoneID != r.RemoteZone || dnsName(z.Name) != r.ZoneName {
		return errConflict
	}
	return nil
}

func (r challengeRecord) client(ctx context.Context, app core.App, resolve dnscatalog.Resolve) (dns.Provider, error) {
	if err := r.authorize(ctx, app); err != nil {
		return nil, err
	}
	if resolve == nil {
		return nil, errProvider
	}
	p, err := resolve(ctx, r.Provider, r.AccessID, false)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, errProvider
	}
	return p, nil
}

func (r challengeRecord) matches(v dns.DNSRecord) bool {
	if dnsName(v.Name) != r.Name || !strings.EqualFold(v.Type, r.Type) {
		return false
	}
	if r.Type == "CNAME" {
		return dnsName(v.Content) == r.Value
	}
	// Some APIs return one quoted DNS character-string for a TXT token.
	return v.Content == r.Value || (!strings.ContainsAny(r.Value, "\\\"") && v.Content == "\""+r.Value+"\"")
}

// Inspect every page before accepting absence. A partially listed zone must
// never lead to creating a duplicate or forgetting an owned record.
func (r challengeRecord) inspect(ctx context.Context, p dns.Provider) (*dns.DNSRecord, error) {
	seen := make(map[string]struct{})
	var found *dns.DNSRecord
	var total int
	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result, err := p.DNSRecords(ctx, r.RemoteZone, page, r.Name)
		if err != nil || result == nil || result.Info.Page != page || result.Info.Total < 0 || page > 1 && result.Info.Total != total {
			return nil, errProvider
		}
		total = result.Info.Total
		for _, v := range result.Items {
			if v.ID == "" {
				return nil, errProvider
			}
			if _, ok := seen[v.ID]; ok {
				return nil, errProvider
			}
			seen[v.ID] = struct{}{}
			if r.RecordID != "" {
				if v.ID != r.RecordID {
					continue
				}
				if !r.matches(v) {
					return nil, errConflict
				}
			} else if !r.matches(v) {
				if dnsName(v.Name) == r.Name && (v.Type == "CNAME" || r.Type == "CNAME") {
					return nil, errConflict
				}
				continue
			}
			if found == nil {
				record := v
				found = &record
			}
		}
		if len(seen) == total {
			return found, nil
		}
		if len(seen) > total || len(result.Items) != dns.DNSPageSize {
			return nil, errProvider
		}
	}
}

func reserveChallenge(app core.App, order string, z *dnscatalog.Domain, c Challenge) (challengeRecord, error) {
	var r challengeRecord
	err := app.RunInTransaction(func(tx core.App) error {
		key := dbx.Params{"provider": z.Provider, "access": z.AccessID, "zone": z.ZoneID, "name": c.Name, "type": c.Type, "value": c.Value}
		err := tx.DB().NewQuery(`SELECT * FROM dns_cert_challenges WHERE provider={:provider} AND access_id={:access} AND remote_zone={:zone} AND name={:name} AND type={:type} AND value={:value}`).Bind(key).One(&r)
		if errors.Is(err, sql.ErrNoRows) {
			r = challengeRecord{ID: core.GenerateDefaultRandomId(), Provider: z.Provider, AccessID: z.AccessID, LocalZone: z.ID, RemoteZone: z.ZoneID, ZoneName: dnsName(z.Name), Name: c.Name, Type: c.Type, Value: c.Value, State: "prepared"}
			_, err = tx.DB().Insert("dns_cert_challenges", dbx.Params{"id": r.ID, "local_zone": r.LocalZone, "provider": r.Provider, "access_id": r.AccessID, "remote_zone": r.RemoteZone, "zone_name": r.ZoneName, "name": r.Name, "type": r.Type, "value": r.Value}).Execute()
		} else if err == nil {
			if r.LocalZone != z.ID || r.ZoneName != dnsName(z.Name) || r.State == "deleting" {
				return errConflict
			}
			if r.State != "owned" && r.State != "external" {
				var count int
				err = tx.DB().NewQuery("SELECT count(*) FROM dns_cert_challenge_refs WHERE order_id={:order} AND challenge_id={:id}").Bind(dbx.Params{"order": order, "id": r.ID}).Row(&count)
				if err == nil && count == 0 {
					return errConflict
				}
			}
		}
		if err != nil {
			return err
		}
		_, err = tx.DB().NewQuery("INSERT INTO dns_cert_challenge_refs(order_id,challenge_id) VALUES({:order},{:id}) ON CONFLICT DO NOTHING").Bind(dbx.Params{"order": order, "id": r.ID}).Execute()
		return err
	})
	return r, err
}

func (r *challengeRecord) save(app core.App, state, id, snapshot string) error {
	err := updated(app.DB().Update("dns_cert_challenges", dbx.Params{"state": state, "record_id": id, "snapshot": snapshot}, dbx.HashExp{"id": r.ID, "state": r.State, "record_id": r.RecordID}).Execute())
	if err == nil {
		r.State, r.RecordID, r.Snapshot = state, id, snapshot
	}
	return err
}

// Only the fingerprint is stored. A provider may attach user comments to DNS records.
func recordFingerprint(r *dns.DNSRecord) (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func (r *challengeRecord) present(ctx context.Context, app core.App, resolve dnscatalog.Resolve) error {
	p, err := r.client(ctx, app, resolve)
	if err != nil {
		return err
	}
	live, err := r.inspect(ctx, p)
	if err != nil {
		return err
	}
	switch r.State {
	case "external", "owned":
		if live == nil {
			return errConflict
		}
		return nil
	case "prepared":
		if live != nil {
			return r.save(app, "external", live.ID, "")
		}
		p, err = r.client(ctx, app, resolve)
		if err != nil {
			return err
		}
		if err = r.save(app, "creating", "", ""); err != nil {
			return err
		}
		ttl := 600
		if r.Provider == "namesilo" {
			ttl = 3600
		}
		id, err := p.CreateDNSRecord(ctx, r.RemoteZone, dns.RecordInput{Name: r.Name, Type: r.Type, Content: r.Value, TTL: ttl})
		if err != nil || id == "" {
			return errProvider
		}
		if err = r.save(app, "creating", id, ""); err != nil {
			return err
		}
		live, err = r.inspect(ctx, p)
		if err != nil {
			return err
		}
	case "creating":
		if r.RecordID == "" && live != nil {
			// An ambiguous create response cannot confer ownership of a
			// record discovered later. It can still satisfy validation.
			return r.save(app, "external", live.ID, "")
		}
	default:
		return errConflict
	}
	if r.RecordID == "" || live == nil {
		return errConflict
	}
	snapshot, err := recordFingerprint(live)
	if err != nil {
		return err
	}
	return r.save(app, "owned", live.ID, snapshot)
}

func presentChallenges(ctx context.Context, app core.App, order, domain, zoneID string, list []Challenge, resolve dnscatalog.Resolve) error {
	if len(list) == 0 {
		return errInput
	}
	if err := validateChallenges(list); err != nil {
		return err
	}
	if err := authorizeChallengeZone(ctx, zoneID); err != nil {
		return err
	}
	z, err := dnscatalog.Lookup(app, zoneID)
	if err != nil {
		return err
	}
	normalized := make([]Challenge, len(list))
	for i, c := range list {
		normalized[i], err = normalizeChallenge(c, dnsName(domain), dnsName(z.Name))
		if err != nil {
			return err
		}
	}
	target := challengeRecord{Provider: z.Provider, AccessID: z.AccessID, LocalZone: z.ID, RemoteZone: z.ZoneID, ZoneName: dnsName(z.Name)}
	for _, c := range normalized {
		if err := target.authorize(ctx, app); err != nil {
			return err
		}
		r, err := reserveChallenge(app, order, z, c)
		if err != nil {
			return err
		}
		if err = r.present(ctx, app, resolve); err != nil {
			return err
		}
	}
	return nil
}

func (r *challengeRecord) release(app core.App, order string) (bool, error) {
	last := false
	err := app.RunInTransaction(func(tx core.App) error {
		var holders int
		if err := tx.DB().NewQuery("SELECT count(*) FROM dns_cert_challenge_refs WHERE challenge_id={:id}").Bind(dbx.Params{"id": r.ID}).Row(&holders); err != nil {
			return err
		}
		if holders == 0 {
			return errConflict
		}
		if holders > 1 {
			return updated(tx.DB().Delete("dns_cert_challenge_refs", dbx.HashExp{"order_id": order, "challenge_id": r.ID}).Execute())
		}
		if r.State == "prepared" || r.State == "external" {
			return updated(tx.DB().Delete("dns_cert_challenges", dbx.HashExp{"id": r.ID, "state": r.State}).Execute())
		}
		if r.State != "deleting" && r.State != "creating" && r.State != "owned" {
			return errConflict
		}
		last = true
		return r.save(tx, "deleting", r.RecordID, r.Snapshot)
	})
	return last, err
}

func cleanChallenges(ctx context.Context, app core.App, order string, resolve dnscatalog.Resolve) error {
	var rows []challengeRecord
	if err := app.DB().NewQuery(`SELECT c.* FROM dns_cert_challenges c JOIN dns_cert_challenge_refs x ON x.challenge_id=c.id WHERE x.order_id={:order} ORDER BY c.id`).Bind(dbx.Params{"order": order}).All(&rows); err != nil {
		return err
	}
	// Check the entire order before making even a local change. Legacy
	// administrative orders may hold records in several DNS accounts.
	for _, r := range rows {
		if err := r.authorize(ctx, app); err != nil {
			return err
		}
	}
	for _, r := range rows {
		if err := r.authorize(ctx, app); err != nil {
			return err
		}
		last, err := r.release(app, order)
		if err != nil {
			return err
		}
		if !last {
			continue
		}
		p, err := r.client(ctx, app, resolve)
		if err != nil {
			return err
		}
		live, err := r.inspect(ctx, p)
		if err != nil {
			return err
		}
		if live != nil {
			snap, err := recordFingerprint(live)
			if err != nil {
				return err
			}
			if r.RecordID == "" || snap != r.Snapshot {
				return errConflict
			}
			p, err = r.client(ctx, app, resolve)
			if err != nil {
				return err
			}
			deleted, err := p.DeleteDNSRecord(ctx, r.RemoteZone, r.RecordID)
			if err != nil || deleted != r.RecordID {
				return errProvider
			}
		}
		if err := updated(app.DB().Delete("dns_cert_challenges", dbx.HashExp{"id": r.ID, "state": "deleting"}).Execute()); err != nil {
			return err
		}
	}
	return nil
}
