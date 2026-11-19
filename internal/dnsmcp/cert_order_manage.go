package dnsmcp

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/dnscert"
)

var certConflict = &opError{409, "Order or renewal changed. Read its status before retrying."}

func certRequest(e *core.RequestEvent, args object, grant scope, provider string, previous *dnscert.OrderRequest) (dnscert.OrderRequest, *opError) {
	var req dnscert.OrderRequest
	if previous != nil {
		req = *previous
	}
	if details, exists := args["request"]; exists {
		fields, ok := details.(map[string]any)
		if !ok {
			return req, invalid
		}
		// Identity and algorithm are set from the audited tool fields below.
		for k := range fields {
			switch k {
			case "email", "contactName", "phone", "organization", "address", "city", "province", "country", "postalCode", "department", "title", "instanceId", "contactId":
			default:
				return req, invalid
			}
		}
		b, err := json.Marshal(fields)
		if err != nil || json.Unmarshal(b, &req) != nil {
			return req, invalid
		}
	}
	if names, exists := args["domains"]; exists {
		data, err := json.Marshal(names)
		var list []string
		if err != nil || json.Unmarshal(data, &list) != nil || len(list) != 1 {
			return req, invalid
		}
		req.Domain = strings.TrimSpace(list[0])
	}
	if id, exists := args["zone_id"]; exists {
		var ok bool
		req.SourceZoneID, ok = id.(string)
		if !ok {
			return req, invalid
		}
	}
	if req.SourceZoneID == "" || req.Domain == "" || !slices.Contains(grant.Zones, req.SourceZoneID) {
		return req, invalid
	}
	z, err := dnsauth.GetZone(e, req.SourceZoneID, true)
	if err != nil || !certWithinZone(req.Domain, z.Name) {
		return req, denied
	}
	if previous != nil && previous.SourceZoneID != req.SourceZoneID {
		return req, denied
	}
	algo, ok := certKeySpec(args, req.Algorithm, provider)
	if !ok {
		return req, unsupported
	}
	req.Algorithm = algo
	return req, nil
}

func certKeySpec(args object, previous, provider string) (string, bool) {
	kind, size := "RSA", "2048"
	if previous != "" {
		if suffix, ok := strings.CutPrefix(previous, "RSA"); ok {
			size = suffix
		} else if suffix, ok := strings.CutPrefix(previous, "EC"); ok {
			kind, size = "ECC", suffix
		} else {
			return "", false
		}
	}
	if _, given := args["keytype"]; given {
		newKind := str(args, "keytype")
		if newKind != kind {
			switch newKind {
			case "RSA":
				size = "2048"
			case "ECC":
				size = "256"
			default:
				return "", false
			}
			kind = newKind
		}
	}
	if _, given := args["keysize"]; given {
		size = str(args, "keysize")
	}
	prefix := kind
	if kind == "ECC" {
		prefix = "EC"
	}
	spec := prefix + size
	return spec, dnscert.SupportsKeyAlgorithm(provider, spec)
}

func certReply(o dnscert.Order) object {
	return object{"code": 0, "data": object{"id": o.ID, "domain": o.Domain, "zone_id": o.PrimaryZoneID, "aid": o.AccessID,
		"type": o.Provider, "state": o.State, "version": o.Version, "steps": o.AllowedActions}}
}

func (s service) certOrderManage(e *core.RequestEvent, grant scope, action string, args object) (object, *opError) {
	if s.cert == nil {
		return nil, certStoreError
	}
	ctx := e.Request.Context()
	if action == "add" {
		aid := str(args, "aid")
		if aid == "-1" {
			return nil, unsupported
		}
		if !slices.Contains(grant.Accounts, aid) {
			return nil, denied
		}
		var provider string
		if err := e.App.DB().NewQuery("SELECT provider FROM access WHERE id={:id} AND deleted='' AND reserve IN ('','ca')").Bind(dbx.Params{"id": aid}).WithContext(ctx).Row(&provider); err != nil {
			return nil, missing
		}
		req, prob := certRequest(e, args, grant, provider, nil)
		if prob != nil {
			return nil, prob
		}
		if !activeGrant(e) {
			return nil, denied
		}
		o, err := s.cert.Draft(ctx, e.App, aid, req)
		if err != nil {
			return nil, certProblem(err)
		}
		return certReply(o), nil
	}
	if action == "batch" {
		return s.certOrderBatch(e, grant, args)
	}
	row, prob := certOrderRow(e.App, str(args, "id"))
	if prob != nil {
		return nil, prob
	}
	if !certOrderAllowed(e, grant, row, true) {
		return nil, missing
	}
	version, ok := number(args, "version", 0, 1, 2147483647)
	if !ok || row.Version != version {
		return nil, certConflict
	}
	if !activeGrant(e) {
		return nil, denied
	}
	if action == "set_auto" {
		requireVersion, ok := number(args, "renewal_version", 0, 0, 2147483647)
		if !ok {
			return nil, invalid
		}
		enabled, ok := certBool(args["isauto"])
		if !ok {
			return nil, invalid
		}
		confirm, _ := certBool(args["confirm_quota"])
		if enabled && !confirm {
			return nil, invalid
		}
		renewal, err := s.cert.SetRenewal(ctx, e.App, row.ID, dnscert.RenewalInput{Version: requireVersion, Enabled: &enabled, ZoneID: row.SourceZoneID, ConfirmQuota: confirm})
		if err != nil {
			return nil, certProblem(err)
		}
		return object{"code": 0, "data": renewal}, nil
	}
	step := action
	input := dnscert.ActionInput{Version: version}
	switch action {
	case "process":
		reset, _ := certBool(args["reset"])
		if reset {
			return nil, invalid
		}
		step = str(args, "step")
		if step == "" {
			step = map[string]string{"draft": "create", "reserved": "submit", "submitting": "refresh", "pending": "refresh", "issued": "download", "revoking": "refresh", "cancelling": "refresh"}[row.State]
		}
		if !slices.Contains([]string{"create", "submit", "recover", "refresh", "present", "verify", "download", "cleanup"}, step) {
			return nil, invalid
		}
		input.RemoteID = str(args, "remote_id")
		input.ZoneID = row.SourceZoneID
	case "edit":
		if aid := str(args, "aid"); aid != "" && aid != row.AccessID {
			return nil, unsupported
		}
		current, err := dnscert.ReadOrder(e.App, row.ID)
		if err != nil {
			return nil, certProblem(err)
		}
		var prev dnscert.OrderRequest
		if err := json.Unmarshal([]byte(current.RequestJSON), &prev); err != nil {
			return nil, certStoreError
		}
		req, problem := certRequest(e, args, grant, row.Provider, &prev)
		if problem != nil {
			return nil, problem
		}
		input.Request = &req
	case "del":
		var refs int
		err := e.App.DB().NewQuery("SELECT count(*) FROM dns_cert_deploy WHERE order_id={:id}").Bind(dbx.Params{"id": row.ID}).Row(&refs)
		if err != nil {
			return nil, certStoreError
		}
		if refs != 0 {
			return nil, certConflict
		}
		step = "delete"
	case "reset", "revoke":
	default:
		return nil, invalid
	}
	ctx = dnscert.WithChallengeZoneGuard(ctx, func(_ context.Context, zoneID string) error {
		if zoneID != row.SourceZoneID || !activeGrant(e) || !certOrderAllowed(e, grant, row, true) {
			return errors.New("challenge outside interface scope")
		}
		return nil
	})
	o, err := s.cert.Act(ctx, e.App, row.ID, step, input)
	if err != nil {
		return nil, certProblem(err)
	}
	return certReply(o), nil
}

// Check every ID before starting. Reset can clean a DNS challenge, so keep each
// confirmed change durable and report partial progress after a later failure.
func (s service) certOrderBatch(e *core.RequestEvent, grant scope, args object) (object, *opError) {
	act := str(args, "act")
	op := map[string]string{"delete": "del", "open": "set_auto", "close": "set_auto", "reset": "reset"}[act]
	permission := map[string]string{"del": "cert.order.delete", "set_auto": "cert.order.renew", "reset": "cert.order.reset"}[op]
	if op == "" {
		return nil, invalid
	}
	if !slices.Contains(grant.Actions, permission) {
		return nil, denied
	}
	var ids []string
	data, err := json.Marshal(args["ids"])
	if err != nil || json.Unmarshal(data, &ids) != nil || len(ids) == 0 || len(ids) > 50 {
		return nil, invalid
	}
	versions, ok := args["versions"].(map[string]any)
	if !ok {
		return nil, invalid
	}
	operations := make([]object, 0, len(ids))
	for i, id := range ids {
		if id == "" || slices.Contains(ids[:i], id) {
			return nil, invalid
		}
		row, prob := certOrderRow(e.App, id)
		if prob != nil {
			return nil, prob
		}
		if !certOrderAllowed(e, grant, row, true) {
			return nil, missing
		}
		input := object{"id": id, "version": versions[id]}
		ver, valid := number(input, "version", 0, 1, 2147483647)
		if !valid || ver != row.Version {
			return nil, certConflict
		}
		if op == "set_auto" {
			enabled := act == "open"
			confirm, _ := certBool(args["confirm_quota"])
			if enabled && !confirm {
				return nil, invalid
			}
			r, err := dnscert.ReadRenewal(e.App, id)
			if err != nil {
				return nil, certProblem(err)
			}
			input["isauto"], input["confirm_quota"], input["renewal_version"] = enabled, confirm, strconv.Itoa(r.Version)
		}
		operations = append(operations, input)
	}
	for i, input := range operations {
		if _, prob := s.certOrderManage(e, grant, op, input); prob != nil {
			if i == 0 {
				return nil, prob
			}
			return partial(i, len(operations), prob.message)
		}
	}
	return object{"code": 0, "completed": len(operations)}, nil
}

func certProblem(err error) *opError {
	status, msg := dnscert.PublicError(err)
	return &opError{status, msg}
}
