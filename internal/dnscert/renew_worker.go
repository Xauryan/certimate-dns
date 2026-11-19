package dnscert

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

const renewStepInterval = time.Minute

// RunRenewals advances one durable step per due schedule. Claiming a schedule
// and allocating its successor are separate local transactions. No provider
// call is made inside either transaction.
func (s *Service) RunRenewals(ctx context.Context, app core.App) error {
	var ids []string
	err := app.DB().NewQuery(`SELECT root_id FROM dns_cert_renewals WHERE enabled=1 AND next_at>0 AND next_at<={:now} AND lease_end<={:now} ORDER BY next_at,root_id LIMIT 25`).
		Bind(dbx.Params{"now": time.Now().Unix()}).WithContext(ctx).Column(&ids)
	if err != nil {
		return err
	}
	var failures []error
	for _, id := range ids {
		if ctx.Err() != nil {
			return errors.Join(append(failures, ctx.Err())...)
		}
		if err := s.runRenewal(ctx, app, id); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (s *Service) runRenewal(ctx context.Context, app core.App, id string) error {
	now, token := time.Now(), core.GenerateDefaultRandomId()
	result, err := app.DB().NewQuery(`UPDATE dns_cert_renewals SET lease={:token},lease_end={:until}
		WHERE root_id={:id} AND enabled=1 AND next_at>0 AND next_at<={:now} AND lease_end<={:now}`).
		Bind(dbx.Params{"id": id, "token": token, "now": now.Unix(), "until": now.Add(3 * time.Minute).Unix()}).WithContext(ctx).Execute()
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil || n == 0 {
		return err
	}
	r, err := ReadRenewal(app, id)
	if err != nil {
		return err
	}
	previousCurrent := r.CurrentOrderID
	r.Status, r.NextAt = "processing", now.Add(renewStepInterval).Unix()
	stepCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	err = s.advanceRenewal(stepCtx, app, &r)
	cancel()
	if err != nil {
		// Temporary transport failures can be inspected again. A lost response
		// to Create is durably marked "creating" by Act and forces review before
		// another quota could be consumed.
		r.Status, r.NextAt = "retry", time.Now().Add(15*time.Minute).Unix()
		if errors.Is(err, errConflict) || errors.Is(err, errMissing) || errors.Is(err, errInput) {
			r.Status, r.NextAt = "needs_review", 0
		}
	}
	fields := dbx.Params{"status": r.Status, "next_at": r.NextAt, "lease": "", "lease_end": 0,
		"current_id": r.CurrentOrderID, "pending_id": r.PendingOrderID, "proof": r.Proof, "stage": r.Stage}
	if saveErr := app.RunInTransaction(func(tx core.App) error {
		if err := updated(tx.DB().Update("dns_cert_renewals", fields, dbx.HashExp{"root_id": id, "lease": token, "version": r.Version}).Execute()); err != nil {
			return err
		}
		if previousCurrent != r.CurrentOrderID {
			src, err := ReadOrder(tx, previousCurrent)
			if err != nil {
				return err
			}
			if err := updated(tx.DB().Update("certificate", dbx.Params{"isRenewed": true}, dbx.HashExp{"id": src.CertificateID, "deleted": "", "isRevoked": false}).Execute()); err != nil {
				return err
			}
			return writeEvent(tx, r.CurrentOrderID, "renewal", "renewed", true)
		}
		if r.Status == "needs_review" {
			return writeEvent(tx, r.CurrentOrderID, "renewal", "needs_review", false)
		}
		return nil
	}); saveErr != nil {
		return saveErr
	}
	if err != nil {
		app.Logger().Warn("Certificate renewal step did not complete", "order", id, "status", r.Status)
	}
	return nil
}

func renewalRequest(source Order, zoneID string) (OrderRequest, error) {
	var req OrderRequest
	if err := json.Unmarshal([]byte(source.RequestJSON), &req); err != nil {
		return req, errConflict
	}
	// The previous cloud instance is already bound. Its id cannot be reused
	// for a new reservation.
	req.InstanceID, req.SourceZoneID = "", zoneID
	if req.Domain != source.Domain || req.Algorithm != source.Algorithm {
		return req, errConflict
	}
	return req, nil
}

func (s *Service) advanceRenewal(ctx context.Context, app core.App, r *Renewal) error {
	src, err := ReadOrder(app, r.CurrentOrderID)
	if err != nil {
		return err
	}
	if src.AccessID != r.AccessID || src.Domain != r.Domain || src.ReplacementID != r.PendingOrderID {
		return errConflict
	}
	account, err := s.account(ctx, app, src.AccessID)
	if err != nil {
		return err
	}
	if account.Provider != src.Provider {
		return errConflict
	}
	z, err := renewalZone(app, src, r.ZoneID)
	if err != nil {
		return err
	}
	if !r.sameZone(z) {
		return errConflict
	}
	ctx = WithChallengeZoneGuard(ctx, func(ctx context.Context, zoneID string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if zoneID != r.ZoneID {
			return errConflict
		}
		z, err := renewalZone(app, src, zoneID)
		if err != nil {
			return err
		}
		if !r.sameZone(z) {
			return errConflict
		}
		return nil
	})
	expiry, err := renewalExpiry(app, src)
	if err != nil {
		return err
	}
	if r.PendingOrderID == "" {
		due := expiry - int64(renewalLead.Seconds())
		if due > time.Now().Unix() {
			r.NextAt, r.Status = due, "scheduled"
			return nil
		}
		// Before reserving a new instance, reconcile the original order against
		// its issuer. Locally expired orders already have a terminal snapshot.
		if src.State == "issued" {
			src, err = s.Act(ctx, app, src.ID, "refresh", ActionInput{Version: src.Version})
			if err != nil {
				return err
			}
			if _, err = renewalExpiry(app, src); err != nil {
				return err
			}
		}
		return s.allocateSuccessor(ctx, app, r, src)
	}

	child, err := ReadOrder(app, r.PendingOrderID)
	if err != nil {
		return err
	}
	expected, err := renewalRequest(src, r.ZoneID)
	if err != nil {
		return err
	}
	var actual OrderRequest
	if json.Unmarshal([]byte(child.RequestJSON), &actual) != nil || expected != actual ||
		child.AccessID != src.AccessID || child.Provider != src.Provider || child.Domain != src.Domain ||
		child.Algorithm != src.Algorithm || child.PrimaryZoneID != r.ZoneID || child.ReplacementID != "" {
		return errConflict
	}
	if child.LeaseEnd > time.Now().Unix() {
		return nil
	}
	action, err := r.nextAction(child)
	if err != nil {
		return err
	}
	if action == "finish" {
		newExpiry, err := renewalExpiry(app, child)
		if err != nil {
			return err
		}
		// Never buy another certificate in response to a duplicate or
		// unexpectedly short-lived issued certificate.
		due := newExpiry - int64(renewalLead.Seconds())
		if newExpiry <= expiry || due <= time.Now().Unix() {
			return errConflict
		}
		r.CurrentOrderID, r.PendingOrderID, r.Stage, r.Proof = child.ID, "", "", ""
		r.Status, r.NextAt = "scheduled", due
		return nil
	}
	_, err = s.Act(ctx, app, child.ID, action, ActionInput{Version: child.Version, ZoneID: r.ZoneID})
	if errors.Is(err, errConflict) && (action == "submit" || action == "verify" || action == "download") {
		// An issuer may finish verification while records are propagating.
		// Refresh the local snapshot before deciding the next transition.
		r.Stage = "reconcile"
		return nil
	}
	if err != nil {
		return err
	}
	switch action {
	case "refresh":
		if r.Stage == "reconcile" {
			r.Stage = ""
		}
	case "present":
		r.Proof = challengeDigest(child.Challenges)
		r.Stage = "verify"
	case "verify":
		r.Stage = "poll"
	case "cleanup":
		r.Stage = "finish"
	}
	return nil
}

func (r Renewal) nextAction(o Order) (string, error) {
	if r.Stage == "reconcile" && (o.State == "pending" || o.State == "issued" || o.State == "reserved") {
		return "refresh", nil
	}
	switch o.State {
	case "draft":
		return "create", nil
	case "reserved":
		return "submit", nil
	case "submitting":
		return "refresh", nil
	case "pending":
		if len(o.Challenges) > 0 {
			if challengeDigest(o.Challenges) != r.Proof {
				return "present", nil
			}
			if r.Stage == "verify" {
				return "verify", nil
			}
		}
		return "refresh", nil
	case "issued":
		if o.CertificateID == "" {
			return "download", nil
		}
		if r.Stage == "finish" {
			return "finish", nil
		}
		return "cleanup", nil
	default:
		return "", errConflict
	}
}

func challengeDigest(challenges []Challenge) string {
	data, _ := json.Marshal(challenges)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func (s *Service) allocateSuccessor(ctx context.Context, app core.App, r *Renewal, src Order) error {
	req, err := renewalRequest(src, r.ZoneID)
	if err != nil {
		return err
	}
	var child Order
	err = app.RunInTransaction(func(tx core.App) error {
		var err error
		child, err = s.Draft(ctx, tx, src.AccessID, req)
		if err != nil {
			return err
		}
		if err := updated(tx.DB().NewQuery(`UPDATE dns_cert_orders SET replacement_id={:child},version=version+1,updated={:now}
			WHERE id={:id} AND version={:v} AND replacement_id='' AND lease_end<={:now}`).
			Bind(dbx.Params{"id": src.ID, "v": src.Version, "child": child.ID, "now": time.Now().Unix()}).Execute()); err != nil {
			return err
		}
		if err := cloneOrderNotification(tx, src.ID, child.ID); err != nil {
			return err
		}
		if _, err := tx.DB().Insert("dns_cert_renewal_orders", dbx.Params{"root_id": r.RootID, "order_id": child.ID}).Execute(); err != nil {
			return err
		}
		return updated(tx.DB().Update("dns_cert_renewals", dbx.Params{"pending_id": child.ID},
			dbx.HashExp{"root_id": r.RootID, "pending_id": "", "lease": r.Lease, "version": r.Version, "enabled": true}).Execute())
	})
	if err == nil {
		r.PendingOrderID = child.ID
	}
	return err
}
