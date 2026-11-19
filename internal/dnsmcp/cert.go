package dnsmcp

import (
	"strings"

	"github.com/pocketbase/pocketbase/core"
)

var certTools = func() []toolDefinition {
	result := []toolDefinition{
		{"cert_order_query", "List authorized commercial CA orders, read their event history, or export the issued key pair.", []operation{
			{"list", "cert.order.read"}, {"get", "cert.order.export"}, {"show_log", "cert.order.log.read"},
		}, []string{"id", "aid", "domain", "type", "status", "include_pfx", "processid", "offset", "limit"}},
		{"cert_order_manage", "Create a zone-bound commercial CA order. Supply its current version for each transition. Renewals require a separate quota confirmation.", []operation{
			{"add", "cert.order.add"}, {"edit", "cert.order.edit"}, {"del", "cert.order.delete"}, {"process", "cert.order.process"},
			{"set_auto", "cert.order.renew"}, {"reset", "cert.order.reset"}, {"revoke", "cert.order.revoke"}, {"batch", "cert.order.batch"},
		}, []string{"id", "ids", "versions", "aid", "domains", "keytype", "keysize", "zone_id", "request", "version", "step", "remote_id", "isauto", "confirm_quota", "renewal_version", "act"}},
	}
	result = append(result, certAccountTools...)
	result = append(result, certDeployTools...)
	return append(result, certCnameTools...)
}()

func (s service) executeCert(e *core.RequestEvent, tool, action string, args object, grant scope) (object, *opError) {
	if !e.HasSuperuserAuth() {
		return nil, denied
	}
	if strings.HasPrefix(tool, "cert_cname_") {
		return s.certCname(e, tool, action, args, grant)
	}
	if !grant.Global {
		return nil, denied
	}
	switch {
	case strings.HasPrefix(tool, "cert_account_"):
		return s.certAccounts(e, tool, action, args, grant)
	case strings.HasPrefix(tool, "cert_deploy_"):
		return s.certDeploy(e, tool, action, args, grant)
	case tool == "cert_order_query":
		return certOrderQuery(e, grant, action, args)
	case tool == "cert_order_manage":
		return s.certOrderManage(e, grant, action, args)
	}
	return nil, invalid
}
