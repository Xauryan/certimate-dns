package dnscert

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/certimate-go/certimate/internal/dnscatalog"
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
)

const renewalLead = 15 * 24 * time.Hour

type Renewal struct {
	Enabled        bool   `json:"enabled" db:"enabled"`
	Version        int    `json:"version" db:"version"`
	ZoneID         string `json:"zoneId" db:"zone_id"`
	Status         string `json:"status" db:"status"`
	NextAt         int64  `json:"nextAt" db:"next_at"`
	CurrentOrderID string `json:"currentOrderId" db:"current_id"`
	PendingOrderID string `json:"pendingOrderId,omitempty" db:"pending_id"`

	RootID       string `json:"-" db:"root_id"`
	AccessID     string `json:"-" db:"access_id"`
	Domain       string `json:"-" db:"domain"`
	ZoneAccount  string `json:"-" db:"zone_account"`
	ZoneProvider string `json:"-" db:"zone_provider"`
	ZoneRemote   string `json:"-" db:"zone_remote"`
	ZoneName     string `json:"-" db:"zone_name"`
	Lease        string `json:"-" db:"lease"`
	LeaseEnd     int64  `json:"-" db:"lease_end"`
	Proof        string `json:"-" db:"proof"`
	Stage        string `json:"-" db:"stage"`
}

type RenewalInput struct {
	Version      int    `json:"version"`
	Enabled      *bool  `json:"enabled"`
	ZoneID       string `json:"zoneId"`
	ConfirmQuota bool   `json:"confirmQuota"`
}

func ReadRenewal(app core.App, orderID string) (Renewal, error) {
	var r Renewal
	err := app.DB().NewQuery(`SELECT r.* FROM dns_cert_renewals r JOIN dns_cert_renewal_orders o ON r.root_id=o.root_id WHERE o.order_id={:id}`).
		Bind(dbx.Params{"id": orderID}).One(&r)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := ReadOrder(app, orderID); err != nil {
			return r, err
		}
		return Renewal{Status: "disabled", RootID: orderID, CurrentOrderID: orderID}, nil
	}
	return r, err
}

func renewalZone(app core.App, o Order, zoneID string) (*dnscatalog.Domain, error) {
	if zoneID == "" || o.PrimaryZoneID != "" && o.PrimaryZoneID != zoneID {
		return nil, errInput
	}
	z, err := dnscatalog.Lookup(app, zoneID)
	if errors.Is(err, domain.ErrRecordNotFound) {
		return nil, errMissing
	}
	if err != nil {
		return nil, err
	}
	name, err := canonicalDomain(z.Name)
	if err != nil || o.Domain != name && !strings.HasSuffix(o.Domain, "."+name) {
		return nil, errInput
	}
	return z, nil
}

// Read only public inventory metadata. The successor must use the same issuer,
// request and DNS account, even across process restarts.
func renewalExpiry(app core.App, o Order) (int64, error) {
	if (o.State != "issued" && o.State != "expired") || o.CertificateID == "" {
		return 0, errConflict
	}
	var expiry sql.NullInt64
	err := app.DB().NewQuery(`SELECT unixepoch(validityNotAfter) FROM certificate WHERE id={:id} AND deleted='' AND isRevoked=0 AND ca={:ca} AND keyAlgorithm={:algorithm}`).
		Bind(dbx.Params{"id": o.CertificateID, "ca": o.Provider, "algorithm": o.Algorithm}).Row(&expiry)
	if errors.Is(err, sql.ErrNoRows) || err == nil && !expiry.Valid {
		return 0, errConflict
	}
	return expiry.Int64, err
}

func (s *Service) SetRenewal(ctx context.Context, app core.App, orderID string, in RenewalInput) (Renewal, error) {
	if in.Enabled == nil || in.Version < 0 || *in.Enabled && (!in.ConfirmQuota || in.ZoneID == "") {
		return Renewal{}, errInput
	}
	now := time.Now().Unix()
	err := app.RunInTransaction(func(tx core.App) error {
		r, err := ReadRenewal(tx, orderID)
		if err != nil {
			return err
		}
		if r.Version != in.Version || r.LeaseEnd > now {
			return errConflict
		}
		if !*in.Enabled {
			if r.Version == 0 {
				return nil
			}
			return updated(tx.DB().Update("dns_cert_renewals", dbx.Params{"enabled": false, "status": "disabled", "next_at": 0, "version": r.Version + 1, "lease": "", "lease_end": 0}, dbx.HashExp{"root_id": r.RootID, "version": r.Version}).Execute())
		}
		o, err := ReadOrder(tx, r.CurrentOrderID)
		if err != nil {
			return err
		}
		if (o.Provider != "aliyun" && o.Provider != "ucloud" && o.Provider != "tencentcloud") || o.ReplacementID != "" && o.ReplacementID != r.PendingOrderID {
			return errConflict
		}
		if _, err := s.account(ctx, tx, o.AccessID); err != nil {
			return err
		}
		z, err := renewalZone(tx, o, in.ZoneID)
		if err != nil {
			return err
		}
		if r.PendingOrderID != "" && !r.sameZone(z) {
			return errConflict
		}
		expiry, err := renewalExpiry(tx, o)
		if err != nil {
			return err
		}
		next := max(now, expiry-int64(renewalLead.Seconds()))
		if r.PendingOrderID != "" {
			next = now
		}
		var other int
		if err := tx.DB().NewQuery(`SELECT count(*) FROM dns_cert_renewals WHERE root_id<>{:root} AND access_id={:account} AND domain={:domain} AND enabled=1`).
			Bind(dbx.Params{"root": r.RootID, "account": o.AccessID, "domain": o.Domain}).Row(&other); err != nil {
			return err
		}
		if other != 0 {
			return errConflict
		}
		fields := dbx.Params{"enabled": true, "version": r.Version + 1, "next_at": next, "status": "scheduled", "zone_id": z.ID, "zone_account": z.AccessID, "zone_name": z.Name, "zone_provider": z.Provider, "zone_remote": z.ZoneID, "lease": "", "lease_end": 0}
		if r.Version != 0 {
			return updated(tx.DB().Update("dns_cert_renewals", fields, dbx.HashExp{"root_id": r.RootID, "version": r.Version}).Execute())
		}
		fields["root_id"], fields["current_id"], fields["access_id"], fields["domain"] = o.ID, o.ID, o.AccessID, o.Domain
		if _, err := tx.DB().Insert("dns_cert_renewals", fields).Execute(); err != nil {
			return err
		}
		_, err = tx.DB().Insert("dns_cert_renewal_orders", dbx.Params{"root_id": o.ID, "order_id": o.ID}).Execute()
		return err
	})
	if err != nil {
		return Renewal{}, err
	}
	return ReadRenewal(app, orderID)
}

func (r Renewal) sameZone(z *dnscatalog.Domain) bool {
	return z.ID == r.ZoneID && z.Provider == r.ZoneProvider && z.ZoneID == r.ZoneRemote && z.AccessID == r.ZoneAccount && strings.EqualFold(z.Name, r.ZoneName)
}

func bindRenew(g *router.RouterGroup[*core.RequestEvent], s *Service) {
	g.GET("/orders/{id}/renewal", func(e *core.RequestEvent) error {
		r, err := ReadRenewal(e.App, e.Request.PathValue("id"))
		return reply(e, r, err)
	})
	g.POST("/orders/{id}/renewal", func(e *core.RequestEvent) error {
		var in RenewalInput
		if e.BindBody(&in) != nil {
			return reply(e, nil, errInput)
		}
		r, err := s.SetRenewal(e.Request.Context(), e.App, e.Request.PathValue("id"), in)
		e.App.Logger().Info("Certificate renewal preference", "actor", e.Auth.Id, "order", e.Request.PathValue("id"), "success", err == nil)
		return reply(e, r, err)
	})
}
