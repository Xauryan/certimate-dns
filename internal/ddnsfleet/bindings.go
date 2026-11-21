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
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type Resolver func(ctx context.Context, provider, accessID, zoneID string) (dns.Provider, error)

type Binding struct {
	ID               string `db:"id" json:"id"`
	NodeID           string `db:"node_id" json:"-"`
	Provider         string `db:"provider" json:"provider"`
	AccessID         string `db:"access_id" json:"accessId"`
	ZoneID           string `db:"zone_id" json:"zoneId"`
	ZoneName         string `db:"zone_name" json:"-"`
	RecordID         string `db:"record_id" json:"recordId"`
	RecordName       string `db:"record_name" json:"recordName"`
	RecordType       string `db:"record_type" json:"recordType"`
	InterfaceName    string `db:"interface_name" json:"interfaceName"`
	LastAddress      string `db:"last_address" json:"lastAddress"`
	SyncStatus       string `db:"sync_status" json:"syncStatus"`
	LastError        string `db:"last_error" json:"lastError"`
	UpdatedAt        string `db:"updated_at" json:"updatedAt"`
	AttemptedAddress string `db:"attempted_address" json:"-"`
	FailureCount     int    `db:"failure_count" json:"-"`
}

func (s *Service) bindBindingRoutes(admin *router.RouterGroup[*core.RequestEvent]) {
	admin.POST("/nodes/{id}/bindings", s.createBinding)
	admin.DELETE("/nodes/{id}/bindings/{bindingId}", s.deleteBinding)
}

func (s *Service) bindings(app core.App) (map[string][]Binding, error) {
	var rows []Binding
	err := app.DB().Select("*").From("ddns_bindings").OrderBy("record_name", "record_type", "id").All(&rows)
	if err != nil {
		return nil, err
	}
	result := make(map[string][]Binding)
	for _, row := range rows {
		result[row.NodeID] = append(result[row.NodeID], row)
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
	var snapshot string
	err := app.DB().Select("interfaces").From("ddns_nodes").Where(dbx.HashExp{"id": nodeID}).WithContext(ctx).Row(&snapshot)
	if errors.Is(err, sql.ErrNoRows) {
		return Binding{}, domain.NewError(404, "DDNS node not found.")
	}
	var interfaces []Interface
	if err != nil || json.Unmarshal([]byte(snapshot), &interfaces) != nil {
		return Binding{}, domain.NewError(500, "Could not read DDNS interfaces.")
	}
	if findInterface(interfaces, input.InterfaceName) == nil {
		return Binding{}, domain.NewError(400, "Select a network interface already reported by this node.")
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

func bindingRequestError(e *core.RequestEvent, err error) error {
	var problem *domain.Error
	if errors.As(err, &problem) {
		return e.Error(problem.Code, problem.Msg, nil)
	}
	return e.InternalServerError("Could not save DDNS binding.", nil)
}
