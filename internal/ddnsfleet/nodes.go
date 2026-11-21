package ddnsfleet

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

type NodeView struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Hostname   string      `json:"hostname"`
	LastSeen   *time.Time  `json:"lastSeen"`
	Enabled    bool        `json:"enabled"`
	Online     bool        `json:"online"`
	Interfaces []Interface `json:"interfaces"`
	Bindings   []Binding   `json:"bindings"`
}

type IssuedToken struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

func validText(value string, max int) bool {
	return len(value) > 0 && len(value) <= max && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}

func hashToken(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func validToken(token string) bool {
	if len(token) != base64.RawURLEncoding.EncodedLen(32) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	return err == nil && len(decoded) == 32
}

func (s *Service) listNodes(e *core.RequestEvent) error {
	e.Response.Header().Set("Cache-Control", "no-store")
	nodes, err := s.ListNodes(e.Request.Context(), e.App)
	if err != nil {
		return e.InternalServerError("Could not read DDNS inventory.", nil)
	}
	return e.JSON(http.StatusOK, nodes)
}

// ListNodes returns the administrative inventory with device credentials excluded.
func (s *Service) ListNodes(ctx context.Context, app core.App) ([]NodeView, error) {
	var rows []struct {
		ID             string `db:"id"`
		Name           string `db:"name"`
		Hostname       string `db:"hostname"`
		Enabled        bool   `db:"enabled"`
		ReportRequired bool   `db:"report_required"`
		SeenAt         int64  `db:"seen_at"`
		Interfaces     string `db:"interfaces"`
	}
	err := app.DB().Select("id", "name", "hostname", "enabled", "report_required", "seen_at", "interfaces").
		From("ddns_nodes").OrderBy("name", "id").WithContext(ctx).All(&rows)
	if err != nil {
		return nil, fmt.Errorf("read DDNS nodes: %w", err)
	}
	bindings, err := s.bindings(app)
	if err != nil {
		return nil, fmt.Errorf("read DDNS bindings: %w", err)
	}
	nodes := make([]NodeView, 0, len(rows))
	since := s.now().Add(-onlineWindow).Unix()
	for _, row := range rows {
		v := NodeView{ID: row.ID, Name: row.Name, Hostname: row.Hostname, Enabled: row.Enabled}
		if err := json.Unmarshal([]byte(row.Interfaces), &v.Interfaces); err != nil {
			return nil, fmt.Errorf("read DDNS interfaces: %w", err)
		}
		if row.SeenAt > 0 {
			seen := time.Unix(row.SeenAt, 0).UTC()
			v.LastSeen = &seen
			v.Online = v.Enabled && !row.ReportRequired && row.SeenAt >= since
		}
		v.Bindings = bindings[row.ID]
		if v.Bindings == nil {
			v.Bindings = []Binding{}
		}
		nodes = append(nodes, v)
	}
	return nodes, nil
}

func (s *Service) createNode(e *core.RequestEvent) error {
	var input struct {
		Name string `json:"name"`
	}
	if err := decodeBody(e, &input); err != nil {
		return err
	}
	issued, err := EnrollNode(e.App, input.Name)
	if errors.Is(err, ErrInvalidName) {
		return e.BadRequestError("Invalid DDNS node name.", nil)
	}
	if err != nil {
		return e.InternalServerError("Could not create DDNS node.", nil)
	}
	e.Response.Header().Set("Cache-Control", "no-store")
	return e.JSON(http.StatusCreated, issued)
}

var (
	ErrInvalidName  = errors.New("invalid DDNS node name")
	ErrNodeNotFound = errors.New("DDNS node not found")
)

// EnrollNode creates an observation-only device identity and returns its one-time token.
func EnrollNode(app core.App, name string) (IssuedToken, error) {
	if !validText(name, 80) {
		return IssuedToken{}, ErrInvalidName
	}
	var rawID [12]byte
	rand.Read(rawID[:])
	id := hex.EncodeToString(rawID[:])
	token := newToken()
	_, err := app.DB().Insert("ddns_nodes", dbx.Params{
		"id": id, "name": name, "token_hash": hashToken(token),
	}).Execute()
	if err != nil {
		return IssuedToken{}, err
	}
	return IssuedToken{ID: id, Token: token}, nil
}

func newToken() string {
	var token [32]byte
	rand.Read(token[:])
	return base64.RawURLEncoding.EncodeToString(token[:])
}

func (s *Service) updateNode(e *core.RequestEvent) error {
	var input struct {
		Name    *string `json:"name"`
		Enabled *bool   `json:"enabled"`
	}
	if err := decodeBody(e, &input); err != nil {
		return err
	}
	changes := dbx.Params{}
	if input.Name != nil {
		if !validText(*input.Name, 80) {
			return e.BadRequestError("Invalid DDNS node name.", nil)
		}
		changes["name"] = *input.Name
	}
	if input.Enabled != nil {
		changes["enabled"] = *input.Enabled
	}
	if len(changes) == 0 {
		return e.BadRequestError("Missing DDNS node changes.", nil)
	}
	if err := s.updateNodeRecord(e.Request.Context(), e.App, e.Request.PathValue("id"), changes); err != nil {
		return nodeMutationError(e, err)
	}
	return e.NoContent(http.StatusNoContent)
}

// SetNodeEnabled pauses or resumes a node for the administrative CLI.
func (s *Service) SetNodeEnabled(ctx context.Context, app core.App, nodeID string, enabled bool) error {
	return s.updateNodeRecord(ctx, app, nodeID, dbx.Params{"enabled": enabled})
}

func (s *Service) updateNodeRecord(ctx context.Context, app core.App, nodeID string, changes dbx.Params) error {
	if enabled, ok := changes["enabled"].(bool); ok && !enabled {
		changes["report_required"] = true
	}
	s.mutations.Lock()
	defer s.mutations.Unlock()
	result, err := app.DB().Update("ddns_nodes", changes, dbx.HashExp{"id": nodeID}).WithContext(ctx).Execute()
	return nodeMutationResult(result, err)
}

func nodeMutationError(e *core.RequestEvent, err error) error {
	if errors.Is(err, ErrNodeNotFound) {
		return e.NotFoundError("DDNS node not found.", nil)
	}
	return e.InternalServerError("Could not save DDNS node changes.", nil)
}

func nodeMutationResult(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNodeNotFound
	}
	return nil
}

func (s *Service) rotateNode(e *core.RequestEvent) error {
	id := e.Request.PathValue("id")
	token := newToken()
	s.mutations.Lock()
	defer s.mutations.Unlock()
	res, err := e.App.DB().Update("ddns_nodes", dbx.Params{"token_hash": hashToken(token), "report_required": true},
		dbx.HashExp{"id": id}).WithContext(e.Request.Context()).Execute()
	if err := nodeMutationResult(res, err); err != nil {
		return nodeMutationError(e, err)
	}
	e.Response.Header().Set("Cache-Control", "no-store")
	return e.JSON(http.StatusOK, IssuedToken{ID: id, Token: token})
}

func (s *Service) deleteNode(e *core.RequestEvent) error {
	s.mutations.Lock()
	defer s.mutations.Unlock()
	res, err := e.App.DB().Delete("ddns_nodes", dbx.HashExp{"id": e.Request.PathValue("id")}).WithContext(e.Request.Context()).Execute()
	if err := nodeMutationResult(res, err); err != nil {
		return nodeMutationError(e, err)
	}
	return e.NoContent(http.StatusNoContent)
}
