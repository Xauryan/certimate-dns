package ddnsfleet

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

const (
	bindingRenamesTable = "ddns_binding_renames"
	renameCancelDelay   = 20 * time.Second
)

type bindingRename struct {
	Target      string `db:"target_name"`
	Interface   string `db:"interface_name"`
	Source      string `db:"source_snapshot"`
	Evidence    string `db:"evidence"`
	Submitted   bool   `db:"submitted"`
	ReportedID  string `db:"reported_id"`
	SubmittedAt int64  `db:"submitted_at"`
	CandidateID string `db:"candidate_id"`
}

func hasBindingRename(ctx context.Context, app core.App, bindingID string) (bool, error) {
	var id string
	err := app.DB().Select("binding_id").From(bindingRenamesTable).
		Where(dbx.HashExp{"binding_id": bindingID}).WithContext(ctx).Row(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func loadBindingRename(ctx context.Context, app core.App, bindingID string) (bindingRename, error) {
	var intent bindingRename
	err := app.DB().Select("target_name", "interface_name", "source_snapshot", "evidence", "submitted", "submitted_at", "reported_id", "candidate_id").
		From(bindingRenamesTable).Where(dbx.HashExp{"binding_id": bindingID}).WithContext(ctx).One(&intent)
	return intent, err
}

func renameConflict(message string) error {
	return domain.NewError(http.StatusConflict, message)
}

func renamePending() error {
	return renameConflict("The DNS rename could not be confirmed. Submit the same name and interface to check it again. A second provider write will not be sent.")
}

// renameBindingRecord runs under Service.mutations, shared by the DDNS worker
// and binding edits. The caller has resolved the live scoped credential and
// normalized the requested owner to an in-zone FQDN.
func (s *Service) renameBindingRecord(ctx context.Context, app core.App, p dns.Provider, b Binding, newOwner, interfaceName string, authorized func() bool) (Binding, error) {
	if authorized == nil || !authorized() {
		return Binding{}, domain.NewError(http.StatusForbidden, "DNS binding edit is no longer authorized.")
	}
	intent, err := loadBindingRename(ctx, app, b.ID)
	switch {
	case err == nil:
		if !sameOwner(intent.Target, newOwner) || intent.Interface != interfaceName {
			return Binding{}, renameConflict("Another DNS rename is pending. Submit its requested name and interface to confirm it first.")
		}
		if intent.Submitted {
			return s.recoverBindingRename(ctx, app, p, b, intent, authorized)
		}
		// A prepared intent is safe to resume: dispatch sets submitted first.
	case !errors.Is(err, sql.ErrNoRows):
		return Binding{}, domain.NewError(http.StatusInternalServerError, "Could not read the DNS rename state.")
	case sameOwner(b.RecordName, newOwner):
		if b.InterfaceName == interfaceName {
			return b, nil
		}
		return s.finishBindingRename(ctx, app, b, b.RecordID, b.RecordName, interfaceName, false)
	default:
		caps, err := dns.RecordEditCapabilitiesForZone(ctx, p, b.ZoneID)
		if err != nil {
			return Binding{}, domain.NewError(http.StatusBadGateway, "Could not read the DNS provider's record capabilities.")
		}
		if !caps.Rename {
			return Binding{}, domain.NewError(http.StatusUnprocessableEntity, "This DNS provider does not support renaming this record.")
		}
		source, err := lookupRecord(ctx, p, b.ZoneID, b.RecordID)
		switch {
		case errors.Is(err, errRecordMissing):
			return Binding{}, renameConflict("The bound DNS record no longer exists.")
		case err != nil:
			return Binding{}, domain.NewError(http.StatusBadGateway, "Could not read the bound DNS record.")
		case !bindableRecord(source, b.ZoneName) || !sameOwner(source.Name, b.RecordName) || !strings.EqualFold(source.Type, b.RecordType):
			return Binding{}, renameConflict("The bound DNS record's owner, type or writability changed.")
		}
		snapshot, err := json.Marshal(source)
		if err != nil {
			return Binding{}, domain.NewError(http.StatusInternalServerError, "Could not capture the DNS rename source.")
		}
		intent = bindingRename{Target: newOwner, Interface: interfaceName, Source: string(snapshot)}
		if _, err := app.DB().Insert(bindingRenamesTable, dbx.Params{
			"binding_id": b.ID, "target_name": intent.Target, "interface_name": intent.Interface,
			"source_snapshot": intent.Source, "created_at": s.now().UTC().Format(time.RFC3339),
		}).WithContext(ctx).Execute(); err != nil {
			return Binding{}, domain.NewError(http.StatusInternalServerError, "Could not prepare the DNS rename.")
		}
	}
	return s.dispatchBindingRename(ctx, app, p, b, intent, authorized)
}

type bindingRenameWriter struct {
	dns.Provider
	dns.RecordEditor
	dispatch func(context.Context, dns.DNSRecord, dns.RecordInput) (string, error)
}

func (w bindingRenameWriter) ZoneRecordEditCapabilities(ctx context.Context, zone string) (dns.RecordEditCapabilities, error) {
	return dns.RecordEditCapabilitiesForZone(ctx, w.Provider, zone)
}

func (w bindingRenameWriter) ReplaceDNSRecord(ctx context.Context, _ string, prior dns.DNSRecord, desired dns.RecordInput) (string, error) {
	return w.dispatch(ctx, prior, desired)
}

func (s *Service) dispatchBindingRename(ctx context.Context, app core.App, p dns.Provider, b Binding, intent bindingRename, authorized func() bool) (Binding, error) {
	var prior dns.DNSRecord
	if json.Unmarshal([]byte(intent.Source), &prior) != nil || prior.ID != b.RecordID || !sameOwner(prior.Name, b.RecordName) || !strings.EqualFold(prior.Type, b.RecordType) {
		return Binding{}, renameConflict("The saved DNS rename source no longer matches this binding.")
	}
	editor, ok := p.(dns.RecordEditor)
	if !ok {
		return Binding{}, domain.NewError(http.StatusUnprocessableEntity, "This DNS provider does not support verified record changes.")
	}
	desired := dns.RecordInput{
		Name: intent.Target, Type: prior.Type, Content: prior.Content, TTL: prior.TTL,
		Line: prior.Line, Description: prior.Description, Weight: prior.Weight,
	}
	var submitted bool
	var prepareErr error
	var nativeErr error
	var evidence dns.RecordRenameEvidence
	var returnedID string
	writer := bindingRenameWriter{Provider: p, RecordEditor: editor}
	writer.dispatch = func(writeCtx context.Context, source dns.DNSRecord, desired dns.RecordInput) (string, error) {
		evidence, prepareErr = dns.ReadRecordRenameEvidence(writeCtx, p, b.ZoneID, b.ZoneName, source, desired.Name, authorized)
		if prepareErr != nil {
			return "", prepareErr
		}
		if err := writeCtx.Err(); err != nil || !authorized() {
			prepareErr = dns.ErrRecordEditDenied
			return "", prepareErr
		}
		proof, err := json.Marshal(evidence)
		if err != nil {
			prepareErr = err
			return "", err
		}
		result, err := app.DB().Update(bindingRenamesTable, dbx.Params{
			"submitted": true, "submitted_at": s.now().UnixMilli(), "evidence": string(proof),
		}, dbx.HashExp{"binding_id": b.ID, "submitted": false}).WithContext(writeCtx).Execute()
		if !matchedRenameRow(result, err) {
			prepareErr = errors.New("could not persist DNS rename submission")
			return "", prepareErr
		}
		if writeCtx.Err() != nil || !authorized() {
			// The durable marker was written, but the provider call has not
			// begun. It is safe to clear here under the binding mutation lock.
			prepareErr = dns.ErrRecordEditDenied
			if err := clearBindingRename(app, b.ID, true); err != nil {
				prepareErr = err
			}
			return "", prepareErr
		}
		submitted = true
		reported, err := editor.ReplaceDNSRecord(writeCtx, b.ZoneID, source, desired)
		nativeErr = err
		if reported != "" && err == nil {
			result, saveErr := app.DB().Update(bindingRenamesTable, dbx.Params{"reported_id": reported},
				dbx.HashExp{"binding_id": b.ID, "submitted": true}).Execute()
			if matchedRenameRow(result, saveErr) {
				returnedID = reported
			}
		}
		return reported, err
	}

	_, err := dns.ReplaceVerified(ctx, writer, b.ZoneID, b.ZoneName, prior, desired, authorized)
	if !submitted {
		// No provider mutation was dispatched. Clear the prepared intent so the
		// administrator can retry after refreshing the source or target.
		if _, clearErr := app.DB().Delete(bindingRenamesTable, dbx.HashExp{"binding_id": b.ID, "submitted": false}).Execute(); clearErr != nil {
			return Binding{}, domain.NewError(http.StatusInternalServerError, "Could not clear the prepared DNS rename.")
		}
		if prepareErr != nil {
			err = prepareErr
		}
		return Binding{}, renameBeforeWriteError(err)
	}
	// A lost provider response can still be reconciled later without a
	// second write. Record a candidate only after a complete fresh readback.
	verified, err := dns.VerifyRecordRename(ctx, p, b.ZoneID, b.ZoneName, prior, intent.Target, returnedID, evidence, authorized)
	if err != nil {
		return Binding{}, renamePending()
	}
	if errors.Is(nativeErr, dns.ErrInvalidDNSRequest) && returnedID == "" && verified.SourceIntact {
		if err := clearBindingRename(app, b.ID, true); err != nil {
			return Binding{}, domain.NewError(http.StatusInternalServerError, "Could not clear the rejected DNS rename.")
		}
		return Binding{}, renameBeforeWriteError(nativeErr)
	}
	return s.applyRenameReadback(ctx, app, b, intent, verified)
}

func matchedRenameRow(result sql.Result, err error) bool {
	if err != nil || result == nil {
		return false
	}
	rows, err := result.RowsAffected()
	return err == nil && rows == 1
}

func readBindingRenameResult(ctx context.Context, p dns.Provider, b Binding, intent bindingRename, authorized func() bool) (dns.RecordRenameReadback, error) {
	var prior dns.DNSRecord
	var evidence dns.RecordRenameEvidence
	if json.Unmarshal([]byte(intent.Source), &prior) != nil || json.Unmarshal([]byte(intent.Evidence), &evidence) != nil ||
		prior.ID != b.RecordID || !sameOwner(prior.Name, b.RecordName) || !strings.EqualFold(prior.Type, b.RecordType) {
		return dns.RecordRenameReadback{}, renameConflict("The saved DNS rename evidence no longer matches this binding.")
	}
	result, err := dns.VerifyRecordRename(ctx, p, b.ZoneID, b.ZoneName, prior, intent.Target, intent.ReportedID, evidence, authorized)
	if errors.Is(err, dns.ErrRecordEditDenied) {
		return result, domain.NewError(http.StatusForbidden, "DNS binding edit is no longer authorized.")
	}
	if err != nil {
		return result, renamePending()
	}
	return result, nil
}

func (s *Service) recoverBindingRename(ctx context.Context, app core.App, p dns.Provider, b Binding, intent bindingRename, authorized func() bool) (Binding, error) {
	result, err := readBindingRenameResult(ctx, p, b, intent, authorized)
	if err != nil {
		return Binding{}, err
	}
	return s.applyRenameReadback(ctx, app, b, intent, result)
}

func (s *Service) applyRenameReadback(ctx context.Context, app core.App, b Binding, intent bindingRename, result dns.RecordRenameReadback) (Binding, error) {
	if result.ConfirmedID != "" {
		return s.finishBindingRename(ctx, app, b, result.ConfirmedID, intent.Target, intent.Interface, true)
	}
	if result.CandidateID != intent.CandidateID {
		res, err := app.DB().Update(bindingRenamesTable, dbx.Params{"candidate_id": result.CandidateID},
			dbx.HashExp{"binding_id": b.ID, "submitted": true}).Execute()
		if !matchedRenameRow(res, err) {
			return Binding{}, renamePending()
		}
	}
	if result.CandidateID != "" {
		return Binding{}, renameConflict("The provider returned no record ID, but a single matching destination was found. Inspect the new record and explicitly confirm it.")
	}
	if result.SourceIntact {
		return Binding{}, renameConflict("The original DNS record is still intact. Recheck this rename or cancel it after the provider request window has elapsed.")
	}
	return Binding{}, renamePending()
}

func (s *Service) cancelBindingRename(ctx context.Context, app core.App, p dns.Provider, b Binding, authorized func() bool) (Binding, error) {
	if authorized == nil || !authorized() {
		return Binding{}, domain.NewError(http.StatusForbidden, "DNS binding edit is no longer authorized.")
	}
	intent, err := loadBindingRename(ctx, app, b.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return b, nil
	}
	if err != nil {
		return Binding{}, domain.NewError(http.StatusInternalServerError, "Could not read the DNS rename state.")
	}
	if intent.Submitted {
		if intent.ReportedID != "" {
			return Binding{}, renameConflict("The provider reported a result. Confirm the DNS rename instead of cancelling it.")
		}
		if s.now().Before(time.UnixMilli(intent.SubmittedAt).Add(renameCancelDelay)) {
			return Binding{}, renameConflict("Allow the provider request window to elapse before cancelling this rename.")
		}
		result, err := readBindingRenameResult(ctx, p, b, intent, authorized)
		if err != nil {
			return Binding{}, err
		}
		if !result.SourceIntact {
			return Binding{}, renameConflict("The provider no longer shows the unchanged source and destination. Verify and confirm the rename instead.")
		}
	}
	if !authorized() {
		return Binding{}, domain.NewError(http.StatusForbidden, "DNS binding edit is no longer authorized.")
	}
	if err := clearBindingRename(app, b.ID, intent.Submitted); err != nil {
		return Binding{}, domain.NewError(http.StatusInternalServerError, "Could not cancel the DNS rename.")
	}
	b.PendingRename = nil
	return b, nil
}

func (s *Service) confirmBindingRename(ctx context.Context, app core.App, p dns.Provider, b Binding, recordID string, authorized func() bool) (Binding, error) {
	if authorized == nil || !authorized() {
		return Binding{}, domain.NewError(http.StatusForbidden, "DNS binding edit is no longer authorized.")
	}
	intent, err := loadBindingRename(ctx, app, b.ID)
	if errors.Is(err, sql.ErrNoRows) && b.RecordID == recordID {
		return b, nil
	}
	if err != nil || !intent.Submitted || intent.ReportedID != "" || recordID == "" || recordID != intent.CandidateID {
		return Binding{}, renameConflict("Recheck the pending rename and select the exact matching destination.")
	}
	result, err := readBindingRenameResult(ctx, p, b, intent, authorized)
	if err != nil {
		return Binding{}, err
	}
	if result.CandidateID != recordID {
		return Binding{}, renameConflict("The selected destination no longer matches the saved DNS rename.")
	}
	return s.finishBindingRename(ctx, app, b, recordID, intent.Target, intent.Interface, true)
}

func clearBindingRename(app core.App, bindingID string, submitted bool) error {
	result, err := app.DB().Delete(bindingRenamesTable, dbx.HashExp{"binding_id": bindingID, "submitted": submitted}).Execute()
	if !matchedRenameRow(result, err) {
		return errors.New("could not clear the saved DNS rename")
	}
	return nil
}

func (s *Service) finishBindingRename(ctx context.Context, app core.App, b Binding, actualID, owner, iface string, clearIntent bool) (Binding, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	lastAddress := b.LastAddress
	if iface != b.InterfaceName {
		lastAddress = ""
	}
	now := s.now().UTC().Format(time.RFC3339)
	err := app.RunInTransaction(func(tx core.App) error {
		result, err := tx.DB().Update("ddns_bindings", dbx.Params{
			"record_id": actualID, "record_name": owner, "interface_name": iface, "last_address": lastAddress,
			"sync_status": "pending", "last_error": "", "updated_at": now, "attempted_address": "", "failure_count": 0,
		}, dbx.HashExp{"id": b.ID, "node_id": b.NodeID, "record_id": b.RecordID, "record_name": b.RecordName}).
			WithContext(ctx).Execute()
		if !matchedRenameRow(result, err) {
			return errors.New("could not update the pinned DNS binding")
		}
		if clearIntent {
			result, err = tx.DB().Delete(bindingRenamesTable, dbx.HashExp{"binding_id": b.ID, "submitted": true}).WithContext(ctx).Execute()
			if !matchedRenameRow(result, err) {
				return errors.New("could not finalize the DNS rename intent")
			}
		}
		return nil
	})
	if err != nil {
		if clearIntent {
			return Binding{}, renameConflict("The DNS record was renamed, but the binding update could not be saved. Submit the same edit to confirm it again.")
		}
		return Binding{}, domain.NewError(http.StatusInternalServerError, "Could not update the DDNS binding.")
	}
	b.RecordID, b.RecordName, b.InterfaceName = actualID, owner, iface
	b.LastAddress, b.SyncStatus, b.LastError, b.UpdatedAt = lastAddress, "pending", "", now
	b.AttemptedAddress, b.FailureCount, b.PendingRename = "", 0, nil
	return b, nil
}

func renameBeforeWriteError(err error) error {
	switch {
	case errors.Is(err, dns.ErrInvalidDNSRequest):
		return domain.NewError(http.StatusUnprocessableEntity, "This DNS provider cannot rename the selected record.")
	case errors.Is(err, dns.ErrRecordEditDenied):
		return domain.NewError(http.StatusForbidden, "DNS binding edit is no longer authorized.")
	case errors.Is(err, dns.ErrRecordEditConflict):
		return renameConflict("The DNS record changed or the requested name already has a conflicting record.")
	default:
		return domain.NewError(http.StatusBadGateway, "Could not verify a safe DNS rename with the provider.")
	}
}
