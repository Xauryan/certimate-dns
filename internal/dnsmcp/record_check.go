package dnsmcp

import (
	"errors"
	"strings"

	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/dnscheck"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func recordCheck(e *core.RequestEvent, p dns.Provider, z dnsauth.Zone, args object) (object, *opError) {
	name := owner(str(args, "name"), z.Name)
	id, typ, value := str(args, "recordid"), strings.ToUpper(str(args, "type")), str(args, "value")
	if !inZone(name, z.Name) || typ == "" || id == "" || value == "" {
		return nil, invalid
	}
	rows, problem := authorizedRecords(e.Request.Context(), p, z)
	if problem != nil {
		return nil, problem
	}
	for _, r := range rows {
		if r.ID != id || !strings.EqualFold(r.Type, typ) || !strings.EqualFold(owner(recordRow(r, z)["Name"].(string), z.Name), name) {
			continue
		}
		result, err := dnscheck.Check(e.Request.Context(), z.Name, name, typ, value)
		if errors.Is(err, dnscheck.ErrInvalid) {
			return nil, invalid
		}
		if err != nil {
			return nil, upstream
		}
		return object{"code": 0, "data": result}, nil
	}
	return nil, missing
}
