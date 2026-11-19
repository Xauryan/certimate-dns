package dnscert

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/certimate-go/certimate/internal/dnscatalog"
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

type Service struct {
	accesses accessReader
	issuer   factory
	resolve  dnscatalog.Resolve
}

type ActionInput struct {
	ConfirmUnbound    bool `json:"confirmUnbound,omitempty"`
	superuserRecovery bool

	Version  int           `json:"version"`
	Request  *OrderRequest `json:"request,omitempty"`
	RemoteID string        `json:"remoteId"`
	ZoneID   string        `json:"zoneId"`
}

func NewService(accesses accessReader, resolve dnscatalog.Resolve) *Service {
	return &Service{accesses: accesses, issuer: newIssuer, resolve: resolve}
}

func (o *Order) project() error {
	if err := json.Unmarshal([]byte(o.ChallengesJSON), &o.Challenges); err != nil {
		return err
	}
	if o.Challenges == nil {
		o.Challenges = []Challenge{}
	}
	o.AllowedActions = o.actions(time.Now())
	return nil
}

func ReadOrder(app core.App, id string) (Order, error) {
	var o Order
	err := app.DB().NewQuery("SELECT * FROM dns_cert_orders WHERE id={:id} AND state != 'deleted'").Bind(dbx.Params{"id": id}).One(&o)
	if errors.Is(err, sql.ErrNoRows) {
		return o, errMissing
	}
	if err == nil {
		err = o.project()
	}
	return o, err
}

func (s *Service) account(ctx context.Context, app core.App, id string) (*domain.Access, error) {
	if id == "" {
		return nil, errInput
	}
	var provider string
	err := app.DB().NewQuery("SELECT a.provider " + issuerAccounts + " AND a.id={:id}").Bind(dbx.Params{"id": id}).WithContext(ctx).Row(&provider)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errMissing
	}
	if err != nil {
		return nil, err
	}
	a, err := s.accesses.GetById(ctx, id)
	if errors.Is(err, domain.ErrRecordNotFound) || (err == nil && a == nil) {
		return nil, errMissing
	}
	if err != nil {
		return nil, err
	}
	if a.Id != id || a.Provider != provider || a.DeletedAt != nil || (a.Reserve != "" && a.Reserve != "ca") {
		return nil, errConflict
	}
	return a, nil
}

func (s *Service) Draft(ctx context.Context, app core.App, accessID string, req OrderRequest) (Order, error) {
	a, err := s.account(ctx, app, accessID)
	if err != nil {
		return Order{}, err
	}
	if err = validateRequest(app, &req, a.Provider); err != nil {
		return Order{}, err
	}
	encoded, err := json.Marshal(req)
	if err != nil {
		return Order{}, errInput
	}
	id, now := core.GenerateDefaultRandomId(), time.Now().Unix()
	err = app.RunInTransaction(func(tx core.App) error {
		_, err := tx.DB().Insert("dns_cert_orders", dbx.Params{
			"id": id, "access_id": a.Id, "provider": a.Provider, "domain": req.Domain, "algorithm": req.Algorithm,
			"primary_zone_id": req.SourceZoneID, "request_json": string(encoded), "state": "draft", "created": now, "updated": now,
		}).WithContext(ctx).Execute()
		if err != nil {
			return err
		}
		return writeEvent(tx, id, "draft", "draft", true)
	})
	if err != nil {
		return Order{}, err
	}
	return ReadOrder(app, id)
}

func updated(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errConflict
	}
	return nil
}

func (o *Order) guardedUpdate(app core.App, fields dbx.Params) error {
	fields["updated"] = time.Now().Unix()
	return updated(app.DB().Update("dns_cert_orders", fields, dbx.HashExp{"id": o.ID, "version": o.Version}).Execute())
}

// Record the mutation intent before sending a request. A crash or an ambiguous
// response leaves a recoverable state. A new order is never purchased on retry.
func (o *Order) mark(app core.App, state string) error {
	if err := o.guardedUpdate(app, dbx.Params{"state": state}); err != nil {
		return err
	}
	o.State = state
	return nil
}

func (s *Service) Act(ctx context.Context, app core.App, id, action string, in ActionInput) (out Order, resultErr error) {
	o, err := ReadOrder(app, id)
	if err != nil {
		return Order{}, err
	}
	if in.Version != o.Version || !slices.Contains(o.AllowedActions, action) {
		return Order{}, errConflict
	}
	if action == "recover" && !remoteIDPattern.MatchString(in.RemoteID) || action == "present" && (in.ZoneID == "" || o.PrimaryZoneID != "" && o.PrimaryZoneID != in.ZoneID) || action == "edit" && in.Request == nil {
		return Order{}, errInput
	}
	// A different process can take over after the maximum outbound deadline.
	now := time.Now().Unix()
	result, err := app.DB().NewQuery(`UPDATE dns_cert_orders SET lease_end={:end},version=version+1,updated={:now}
        WHERE id={:id} AND version={:version} AND lease_end <= {:now}`).
		Bind(dbx.Params{"id": id, "version": o.Version, "end": now + 180, "now": now}).WithContext(ctx).Execute()
	if err := updated(result, err); err != nil {
		return Order{}, err
	}
	o.Version++
	defer func() {
		err := app.RunInTransaction(func(tx core.App) error {
			if err := o.guardedUpdate(tx, dbx.Params{"lease_end": 0}); err != nil {
				return err
			}
			var persistedState string
			if err := tx.DB().NewQuery("SELECT state FROM dns_cert_orders WHERE id={:id}").Bind(dbx.Params{"id": id}).Row(&persistedState); err != nil {
				return err
			}
			return writeEvent(tx, id, action, persistedState, resultErr == nil)
		})
		if err != nil && resultErr == nil {
			resultErr = err
			out = Order{}
		}
		if resultErr == nil && out.ID == id {
			out.LeaseEnd = 0
			out.AllowedActions = out.actions(time.Now())
		}
	}()
	var req OrderRequest
	if err := json.Unmarshal([]byte(o.RequestJSON), &req); err != nil {
		return Order{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	switch {
	case action == "edit":
		a, err := s.account(ctx, app, o.AccessID)
		if err != nil {
			return Order{}, err
		}
		if a.Provider != o.Provider {
			return Order{}, errConflict
		}
		next := *in.Request
		if err := validateRequest(app, &next, o.Provider); err != nil {
			return Order{}, err
		}
		if o.PrimaryZoneID != "" && next.SourceZoneID != o.PrimaryZoneID {
			return Order{}, errConflict
		}
		data, err := json.Marshal(next)
		if err != nil {
			return Order{}, err
		}
		if err = o.guardedUpdate(app, dbx.Params{"request_json": string(data), "primary_zone_id": next.SourceZoneID, "domain": next.Domain, "algorithm": next.Algorithm}); err != nil {
			return Order{}, err
		}
	case action == "delete":
		var refs int
		if err := app.DB().NewQuery("SELECT EXISTS(SELECT 1 FROM dns_cert_orders WHERE replacement_id={:id}) OR EXISTS(SELECT 1 FROM dns_cert_deploy WHERE order_id={:id})").Bind(dbx.Params{"id": id}).Row(&refs); err != nil {
			return Order{}, err
		}
		if refs != 0 {
			return Order{}, errConflict
		}
		o.State = "deleted"
		if err := o.guardedUpdate(app, dbx.Params{"state": o.State, "request_json": "{}"}); err != nil {
			return Order{}, err
		}
		o.AllowedActions = nil
		o.RequestJSON = "{}"
		return o, nil
	case action == "reset":
		if err := cleanChallenges(ctx, app, id, s.resolve); err != nil {
			return Order{}, err
		}
		var next Order
		err := app.RunInTransaction(func(tx core.App) error {
			var err error
			next, err = s.Draft(ctx, tx, o.AccessID, req)
			if err != nil {
				return err
			}
			if err := cloneOrderNotification(tx, o.ID, next.ID); err != nil {
				return err
			}
			return o.guardedUpdate(tx, dbx.Params{"replacement_id": next.ID})
		})
		return next, err
	case action == "cancel" && o.State == "draft":
		o.State = "cancelled"
	case action == "cleanup":
		if err := cleanChallenges(ctx, app, o.ID, s.resolve); err != nil {
			return Order{}, err
		}
	case action == "present":
		if err := presentChallenges(ctx, app, o.ID, o.Domain, in.ZoneID, o.Challenges, s.resolve); err != nil {
			return Order{}, err
		}
	default:
		a, err := s.account(ctx, app, o.AccessID)
		if err != nil {
			return Order{}, err
		}
		if a.Provider != o.Provider {
			return Order{}, errConflict
		}
		issuer, err := s.issuer(a)
		if err != nil {
			return Order{}, err
		}
		var material *Material
		material, err = s.perform(ctx, app, &o, req, issuer, action, in)
		if err != nil {
			return Order{}, err
		}
		err = app.RunInTransaction(func(tx core.App) error {
			if (action == "create" || action == "recover") && o.RemoteID != "" {
				var linked int
				if err := tx.DB().NewQuery(`SELECT count(*) FROM dns_cert_orders WHERE id!={:id} AND access_id={:access} AND remote_id={:remote} AND state NOT IN ('cancelled','revoked','expired','failed')`).Bind(dbx.Params{"id": o.ID, "access": o.AccessID, "remote": o.RemoteID}).Row(&linked); err != nil {
					return err
				}
				if linked != 0 {
					return errConflict
				}
			}
			if material != nil {
				certID, err := storeMaterial(tx, req, o.Provider, *material)
				if err != nil {
					return err
				}
				o.CertificateID = certID
			}
			if o.State == "revoked" && o.CertificateID != "" {
				if err := markRevoked(tx, o.CertificateID); err != nil {
					return err
				}
			}
			return saveOrder(tx, &o)
		})
		if err != nil {
			return Order{}, err
		}
		if o.State == "cancelled" || o.State == "revoked" || o.State == "failed" || o.State == "expired" {
			if err := cleanChallenges(ctx, app, id, s.resolve); err != nil {
				return Order{}, err
			}
		}
		return ReadOrder(app, id)
	}
	if err := saveOrder(app, &o); err != nil {
		return Order{}, err
	}
	return ReadOrder(app, id)
}

func saveOrder(app core.App, o *Order) error {
	challenges, err := json.Marshal(o.Challenges)
	if err != nil {
		return err
	}
	return o.guardedUpdate(app, dbx.Params{"state": o.State, "remote_id": o.RemoteID, "certificate_id": o.CertificateID, "challenges_json": string(challenges)})
}

func (s *Service) perform(ctx context.Context, app core.App, o *Order, req OrderRequest, issuer Issuer, action string, in ActionInput) (*Material, error) {
	if action == "create" {
		if a, ok := issuer.(*aliyunIssuer); ok {
			var ids []string
			err := app.DB().NewQuery(`SELECT remote_id FROM dns_cert_orders WHERE access_id={:access} AND remote_id<>'' AND state NOT IN ('cancelled','revoked','expired','failed')`).Bind(dbx.Params{"access": o.AccessID}).Column(&ids)
			if err != nil {
				return nil, err
			}
			skip := make(map[string]bool, len(ids))
			for _, id := range ids {
				skip[id] = true
			}
			id, err := a.selectInstance(ctx, req, skip)
			if err != nil {
				return nil, err
			}
			if !remoteIDPattern.MatchString(id) {
				return nil, errProvider
			}
			o.RemoteID, o.State = id, "reserved"
			return nil, nil
		}
		if err := o.mark(app, "creating"); err != nil {
			return nil, err
		}
		id, err := issuer.Create(ctx, req)
		if err != nil {
			return nil, err
		}
		if !remoteIDPattern.MatchString(id) {
			return nil, errProvider
		}
		o.RemoteID = id
		if o.Provider == "tencentcloud" {
			o.State = "pending"
		} else {
			o.State = "reserved"
		}
		return nil, nil
	}
	id := o.RemoteID
	if action == "recover" {
		id = in.RemoteID
	}
	snap, err := issuer.Inspect(ctx, id)
	if err != nil {
		return nil, err
	}
	allowUnbound := action == "recover" && o.Provider == "ucloud" && in.ConfirmUnbound && in.superuserRecovery && snap.State == "reserved"
	if err = snap.validate(*o, action == "recover" && !allowUnbound); err != nil {
		return nil, err
	}
	switch action {
	case "recover", "refresh":
		// Some providers recycle a cancelled instance and return it to their
		// free pool. It must never become a new reservation of this old order.
		if o.State == "cancelling" && snap.State == "reserved" {
			snap.State = "cancelled"
		}
		if snap.State == "reserved" && !slices.Contains([]string{"reserved", "submitting", "creating"}, o.State) {
			return nil, errConflict
		}
		if (o.State == "revoking" && snap.State == "issued") || (o.State == "cancelling" && snap.State == "pending") {
			return nil, nil
		}
		o.RemoteID, o.State = id, snap.State
		// Some APIs omit the revoke challenge on subsequent reads.
		if o.State != "revoking" || len(snap.Challenges) > 0 {
			o.Challenges = snap.Challenges
		}
	case "submit":
		if snap.State != "reserved" {
			return nil, errConflict
		}
		if err := o.mark(app, "submitting"); err != nil {
			return nil, err
		}
		if err := issuer.Submit(ctx, id, req); err != nil {
			return nil, err
		}
		o.State = "pending"
	case "verify":
		if snap.State != "pending" {
			return nil, errConflict
		}
		if err := issuer.Verify(ctx, id); err != nil {
			return nil, err
		}
		o.Challenges = snap.Challenges
	case "download":
		if snap.State != "issued" {
			return nil, errConflict
		}
		material, err := issuer.Download(ctx, id)
		return &material, err
	case "cancel":
		if snap.State != "reserved" && snap.State != "pending" {
			return nil, errConflict
		}
		if err := o.mark(app, "cancelling"); err != nil {
			return nil, err
		}
		if err := issuer.Cancel(ctx, id); err != nil {
			return nil, err
		}
		o.Challenges = nil
	case "revoke":
		if snap.State != "issued" {
			return nil, errConflict
		}
		if err := o.mark(app, "revoking"); err != nil {
			return nil, err
		}
		list, err := issuer.Revoke(ctx, id)
		if err != nil {
			return nil, err
		}
		if err = validateChallenges(list); err != nil {
			return nil, err
		}
		o.Challenges = list
	default:
		return nil, errInput
	}
	return nil, nil
}
