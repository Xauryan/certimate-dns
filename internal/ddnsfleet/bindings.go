package ddnsfleet

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"

	"github.com/certimate-go/certimate/internal/dnscatalog"
	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type Resolver func(ctx context.Context, provider, accessID, zoneID string) (dns.Provider, error)

type Binding struct {
	ID               string                `db:"id" json:"id"`
	NodeID           string                `db:"node_id" json:"-"`
	Provider         string                `db:"provider" json:"provider"`
	AccessID         string                `db:"access_id" json:"accessId"`
	ZoneID           string                `db:"zone_id" json:"zoneId"`
	ZoneName         string                `db:"zone_name" json:"zoneName"`
	RecordID         string                `db:"record_id" json:"recordId"`
	RecordName       string                `db:"record_name" json:"recordName"`
	RecordType       string                `db:"record_type" json:"recordType"`
	InterfaceName    string                `db:"interface_name" json:"interfaceName"`
	LastAddress      string                `db:"last_address" json:"lastAddress"`
	SyncStatus       string                `db:"sync_status" json:"syncStatus"`
	LastError        string                `db:"last_error" json:"lastError"`
	UpdatedAt        string                `db:"updated_at" json:"updatedAt"`
	AttemptedAddress string                `db:"attempted_address" json:"-"`
	FailureCount     int                   `db:"failure_count" json:"-"`
	PendingRename    *PendingBindingRename `db:"-" json:"pendingRename,omitempty"`
}

type PendingBindingRename struct {
	RecordName        string `json:"recordName"`
	InterfaceName     string `json:"interfaceName"`
	Submitted         bool   `json:"submitted"`
	CandidateRecordID string `json:"candidateRecordId,omitempty"`
}

func (s *Service) bindBindingRoutes(admin *router.RouterGroup[*core.RequestEvent]) {
	admin.POST("/nodes/{id}/bindings", s.createBinding)
	admin.PUT("/nodes/{id}/bindings/{bindingId}", s.updateBinding)
	admin.DELETE("/nodes/{id}/bindings/{bindingId}/rename", s.cancelRename)
	admin.POST("/nodes/{id}/bindings/{bindingId}/rename/confirm", s.confirmRename)
	admin.DELETE("/nodes/{id}/bindings/{bindingId}", s.deleteBinding)
}

func (s *Service) bindings(app core.App) (map[string][]Binding, error) {
	var rows []struct {
		Binding
		RenameTarget    string `db:"rename_target"`
		RenameInterface string `db:"rename_interface"`
		RenameSubmitted bool   `db:"rename_submitted"`
		RenameCandidate string `db:"rename_candidate"`
	}
	err := app.DB().NewQuery(`SELECT b.*, COALESCE(r.target_name, '') AS rename_target,
			COALESCE(r.interface_name, '') AS rename_interface, COALESCE(r.submitted, 0) AS rename_submitted,
			COALESCE(r.candidate_id, '') AS rename_candidate
		FROM ddns_bindings b LEFT JOIN ddns_binding_renames r ON r.binding_id=b.id
		ORDER BY b.record_name, b.record_type, b.id`).All(&rows)
	if err != nil {
		return nil, err
	}
	result := make(map[string][]Binding)
	for _, row := range rows {
		b := row.Binding
		if row.RenameTarget != "" {
			b.PendingRename = &PendingBindingRename{
				RecordName: row.RenameTarget, InterfaceName: row.RenameInterface,
				Submitted: row.RenameSubmitted, CandidateRecordID: row.RenameCandidate,
			}
		}
		result[b.NodeID] = append(result[b.NodeID], b)
	}
	return result, nil
}

type BindingInput struct {
	Provider      string `json:"provider"`
	AccessID      string `json:"accessId"`
	ZoneID        string `json:"zoneId"`
	RecordID      string `json:"recordId"`
	InterfaceName string `json:"interfaceName"`
}

func (s *Service) createBinding(e *core.RequestEvent) error {
	var input BindingInput
	if err := decodeBody(e, &input); err != nil {
		return err
	}
	b, err := s.CreateBinding(e.Request.Context(), e.App, e.Request.PathValue("id"), input)
	if err != nil {
		return bindingRequestError(e, err)
	}
	return e.JSON(http.StatusCreated, b)
}

func (s *Service) CreateBinding(ctx context.Context, app core.App, nodeID string, input BindingInput) (Binding, error) {
	if !dns.IsSupportedProvider(input.Provider) || !validText(input.AccessID, 128) || !validText(input.ZoneID, 512) ||
		!validText(input.RecordID, 512) || !validText(input.InterfaceName, 128) {
		return Binding{}, domain.NewError(400, "Invalid DDNS binding.")
	}

	s.mutations.Lock()
	defer s.mutations.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := requireBindingInterface(ctx, app, nodeID, input.InterfaceName); err != nil {
		return Binding{}, err
	}
	zone, err := dnscatalog.LookupZone(app, input.Provider, input.AccessID, input.ZoneID)
	if err != nil {
		return Binding{}, domain.NewError(404, "DNS catalog zone is unavailable.")
	}
	b := Binding{
		ID: strings.ToLower(rand.Text()), NodeID: nodeID, Provider: input.Provider,
		AccessID: input.AccessID, ZoneID: input.ZoneID, ZoneName: zone.Name,
		RecordID: input.RecordID, InterfaceName: input.InterfaceName,
		SyncStatus: "pending", UpdatedAt: s.now().UTC().Format(time.RFC3339),
	}

	p, err := s.resolve(ctx, b.Provider, b.AccessID, b.ZoneID)
	if err != nil {
		return Binding{}, domain.NewError(http.StatusBadGateway, "Could not resolve DNS credential.")
	}
	if _, ok := p.(dns.RecordEditor); !ok {
		return Binding{}, domain.NewError(400, "This DNS provider does not support verified record updates.")
	}
	record, err := lookupRecord(ctx, p, b.ZoneID, b.RecordID)
	switch {
	case errors.Is(err, errRecordMissing):
		return Binding{}, domain.NewError(404, "DNS record not found in the selected zone.")
	case err != nil:
		return Binding{}, domain.NewError(http.StatusBadGateway, "Could not verify the selected DNS record.")
	case !bindableRecord(record, b.ZoneName):
		return Binding{}, domain.NewError(400, "Select an existing writable A or AAAA record.")
	}
	b.RecordName, b.RecordType = record.Name, strings.ToUpper(record.Type)
	// The owner and zone have already been validated by bindableRecord.
	relative, _ := dnsutil.RelativeName(b.RecordName, b.ZoneName)
	zoneName, _ := dnsutil.ZoneName(b.ZoneName)
	if err := requireFreeRenameTarget(ctx, app, b, dnsutil.FullName(relative, zoneName)); err != nil {
		return Binding{}, err
	}
	res, err := app.DB().NewQuery(`INSERT INTO ddns_bindings
		(id, node_id, provider, access_id, zone_id, zone_name, record_id, record_name, record_type, interface_name, updated_at)
		VALUES ({:id}, {:node}, {:provider}, {:access}, {:zone}, {:zoneName}, {:record}, {:name}, {:type}, {:interface}, {:now})
		ON CONFLICT (provider, zone_id, record_id) DO NOTHING`).Bind(dbx.Params{
		"id": b.ID, "node": b.NodeID, "provider": b.Provider, "access": b.AccessID,
		"zone": b.ZoneID, "zoneName": b.ZoneName, "record": b.RecordID, "name": b.RecordName,
		"type": b.RecordType, "interface": b.InterfaceName, "now": b.UpdatedAt,
	}).WithContext(ctx).Execute()
	if err != nil {
		return Binding{}, domain.NewError(500, "Could not save DDNS binding.")
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return Binding{}, domain.NewError(500, "Could not save DDNS binding.")
	}
	if changed == 0 {
		return Binding{}, domain.NewError(http.StatusConflict, "This DNS record already has a DDNS binding.")
	}
	return b, nil
}

type bindingEditInput struct {
	RecordName            string `json:"recordName"`
	InterfaceName         string `json:"interfaceName"`
	ExpectedRecordName    string `json:"expectedRecordName"`
	ExpectedInterfaceName string `json:"expectedInterfaceName"`
}

func (s *Service) updateBinding(e *core.RequestEvent) error {
	var input bindingEditInput
	if err := decodeBody(e, &input); err != nil {
		return err
	}
	b, err := s.editBinding(e.Request.Context(), e.App, e.Request.PathValue("id"), e.Request.PathValue("bindingId"), input)
	if err != nil {
		return bindingRequestError(e, err)
	}
	return e.JSON(http.StatusOK, b)
}

func (s *Service) editBinding(ctx context.Context, app core.App, nodeID, bindingID string, input bindingEditInput) (Binding, error) {
	if !validText(input.InterfaceName, 128) || !validText(input.ExpectedInterfaceName, 128) {
		return Binding{}, domain.NewError(http.StatusBadRequest, "Invalid DDNS interface.")
	}
	s.mutations.Lock()
	defer s.mutations.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	b, err := loadBinding(ctx, app, nodeID, bindingID)
	if err != nil {
		return Binding{}, err
	}
	owner, err := bindingOwner(input.RecordName, b.ZoneName)
	if err != nil {
		return Binding{}, err
	}
	expected, err := bindingOwner(input.ExpectedRecordName, b.ZoneName)
	if err != nil {
		return Binding{}, err
	}
	current, err := bindingOwner(b.RecordName, b.ZoneName)
	if err != nil {
		return Binding{}, domain.NewError(http.StatusConflict, "The current DDNS record name is unavailable.")
	}
	alreadyDone := current == owner && b.InterfaceName == input.InterfaceName
	if !alreadyDone && (current != expected || b.InterfaceName != input.ExpectedInterfaceName) {
		return Binding{}, domain.NewError(http.StatusConflict, "DDNS binding changed; refresh the binding and try again.")
	}
	if !alreadyDone {
		submitted, err := hasSubmittedRename(ctx, app, nodeID, bindingID)
		if err != nil {
			return Binding{}, domain.NewError(500, "Could not verify the DDNS binding state.")
		}
		if !submitted {
			if err := requireBindingInterface(ctx, app, nodeID, input.InterfaceName); err != nil {
				return Binding{}, err
			}
			if err := requireFreeRenameTarget(ctx, app, b, owner); err != nil {
				return Binding{}, err
			}
		}
	}
	p, scopeValid, err := s.bindingEditProvider(ctx, app, b)
	if err != nil {
		return Binding{}, err
	}
	return s.renameBindingRecord(ctx, app, p, b, owner, input.InterfaceName, scopeValid)
}

func (s *Service) cancelRename(e *core.RequestEvent) error {
	return s.resolvePendingRename(e, "")
}

func (s *Service) confirmRename(e *core.RequestEvent) error {
	var input struct {
		RecordID string `json:"recordId"`
	}
	if err := decodeBody(e, &input); err != nil {
		return err
	}
	if !validText(input.RecordID, 512) {
		return e.BadRequestError("Invalid DNS record ID.", nil)
	}
	return s.resolvePendingRename(e, input.RecordID)
}

func (s *Service) resolvePendingRename(e *core.RequestEvent, candidateID string) error {
	s.mutations.Lock()
	defer s.mutations.Unlock()
	ctx, cancel := context.WithTimeout(e.Request.Context(), 45*time.Second)
	defer cancel()
	nodeID, bindingID := e.Request.PathValue("id"), e.Request.PathValue("bindingId")
	b, err := loadBinding(ctx, e.App, nodeID, bindingID)
	if err != nil {
		return bindingRequestError(e, err)
	}
	submitted, err := hasSubmittedRename(ctx, e.App, nodeID, bindingID)
	if err != nil {
		return e.InternalServerError("Could not verify the DDNS binding state.", nil)
	}
	var p dns.Provider
	scopeValid := e.HasSuperuserAuth
	if submitted {
		p, scopeValid, err = s.bindingEditProvider(ctx, e.App, b)
		if err != nil {
			return bindingRequestError(e, err)
		}
	}
	if candidateID == "" {
		b, err = s.cancelBindingRename(ctx, e.App, p, b, scopeValid)
	} else {
		b, err = s.confirmBindingRename(ctx, e.App, p, b, candidateID, scopeValid)
	}
	if err != nil {
		return bindingRequestError(e, err)
	}
	return e.JSON(http.StatusOK, b)
}

func loadBinding(ctx context.Context, app core.App, nodeID, bindingID string) (Binding, error) {
	var b Binding
	err := app.DB().Select("*").From("ddns_bindings").Where(dbx.HashExp{
		"id": bindingID, "node_id": nodeID,
	}).WithContext(ctx).One(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return Binding{}, domain.NewError(http.StatusNotFound, "DDNS binding not found.")
	}
	if err != nil {
		return Binding{}, domain.NewError(http.StatusInternalServerError, "Could not read DDNS binding.")
	}
	return b, nil
}

func (s *Service) bindingEditProvider(ctx context.Context, app core.App, b Binding) (dns.Provider, func() bool, error) {
	scopeValid := func() bool {
		zone, err := dnscatalog.LookupZone(app, b.Provider, b.AccessID, b.ZoneID)
		return err == nil && sameOwner(zone.Name, b.ZoneName)
	}
	if !scopeValid() {
		return nil, nil, domain.NewError(http.StatusNotFound, "DNS catalog zone is unavailable.")
	}
	p, err := s.resolve(ctx, b.Provider, b.AccessID, b.ZoneID)
	if err != nil {
		return nil, nil, domain.NewError(http.StatusBadGateway, "Could not resolve DNS credential.")
	}
	return p, scopeValid, nil
}

func bindingOwner(raw, zone string) (string, error) {
	invalid := domain.NewError(http.StatusBadRequest, "Enter a record name within the current DNS zone.")
	if !validText(raw, 254) {
		return "", invalid
	}
	zone, err := dnsutil.ZoneName(zone)
	if err != nil {
		return "", invalid
	}
	// Treat dotted input as an explicit DNS name to avoid appending the
	// zone silently when the administrator enters an out-of-zone domain.
	if !strings.Contains(raw, ".") {
		raw = dnsutil.FullName(raw, zone)
	}
	relative, err := dnsutil.RelativeName(raw, zone)
	if err != nil {
		return "", invalid
	}
	return dnsutil.FullName(relative, zone), nil
}

func requireBindingInterface(ctx context.Context, app core.App, nodeID, interfaceName string) error {
	var snapshot string
	err := app.DB().Select("interfaces").From("ddns_nodes").Where(dbx.HashExp{"id": nodeID}).WithContext(ctx).Row(&snapshot)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.NewError(404, "DDNS node not found.")
	}
	var interfaces []Interface
	if err != nil || json.Unmarshal([]byte(snapshot), &interfaces) != nil {
		return domain.NewError(500, "Could not read DDNS interfaces.")
	}
	if findInterface(interfaces, interfaceName) == nil {
		return domain.NewError(400, "Select a network interface already reported by this node.")
	}
	return nil
}

func (s *Service) deleteBinding(e *core.RequestEvent) error {
	err := s.DeleteBinding(e.Request.Context(), e.App, e.Request.PathValue("id"), e.Request.PathValue("bindingId"))
	if err != nil {
		return bindingRequestError(e, err)
	}
	return e.NoContent(http.StatusNoContent)
}

func (s *Service) DeleteBinding(ctx context.Context, app core.App, nodeID, bindingID string) error {
	s.mutations.Lock()
	defer s.mutations.Unlock()
	renaming, err := hasSubmittedRename(ctx, app, nodeID, bindingID)
	if err != nil {
		return domain.NewError(500, "Could not verify the DDNS binding state.")
	}
	if renaming {
		return domain.NewError(http.StatusConflict, "A submitted DDNS rename must be resolved before deleting the binding.")
	}
	res, err := app.DB().Delete("ddns_bindings", dbx.HashExp{
		"id": bindingID, "node_id": nodeID,
	}).WithContext(ctx).Execute()
	if err != nil {
		return domain.NewError(500, "Could not remove DDNS binding.")
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return domain.NewError(500, "Could not remove DDNS binding.")
	}
	if changed == 0 {
		return domain.NewError(404, "DDNS binding not found.")
	}
	return nil
}

func hasSubmittedRename(ctx context.Context, app core.App, nodeID, bindingID string) (bool, error) {
	var renaming bool
	err := app.DB().NewQuery(`SELECT EXISTS (
		SELECT 1 FROM ddns_binding_renames r JOIN ddns_bindings b ON b.id=r.binding_id
		WHERE r.submitted=1 AND b.node_id={:node} AND ({:binding}='' OR b.id={:binding})
	)`).Bind(dbx.Params{"node": nodeID, "binding": bindingID}).WithContext(ctx).Row(&renaming)
	return renaming, err
}

func requireFreeRenameTarget(ctx context.Context, app core.App, b Binding, name string) error {
	var occupied bool
	err := app.DB().NewQuery(`SELECT EXISTS (
		SELECT 1 FROM ddns_binding_renames r JOIN ddns_bindings b ON b.id=r.binding_id
		WHERE b.provider={:provider} AND b.zone_id={:zone} AND b.record_type={:type}
			AND r.target_name={:name} AND b.id<>{:id}
	)`).Bind(dbx.Params{
		"provider": b.Provider, "zone": b.ZoneID, "type": b.RecordType, "name": name, "id": b.ID,
	}).WithContext(ctx).Row(&occupied)
	if err != nil {
		return domain.NewError(500, "Could not verify the DDNS record assignment.")
	}
	if occupied {
		return domain.NewError(http.StatusConflict, "Another DDNS binding has a pending rename to this record.")
	}
	return nil
}

func bindingRequestError(e *core.RequestEvent, err error) error {
	var problem *domain.Error
	if errors.As(err, &problem) {
		return e.Error(problem.Code, problem.Msg, nil)
	}
	return e.InternalServerError("Could not save DDNS binding.", nil)
}
