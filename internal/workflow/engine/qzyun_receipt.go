package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/certimate-go/certimate/internal/domain"
)

var qzyunDocumentIDPattern = regexp.MustCompile(`^[a-zA-Z0-9]{24}$`)

// Scope the remote ID to the tenant and destination that produced it. An
// administrator can change the login on an existing access record.
func qzyunBindingHash(cfg domain.WorkflowNodeConfigForBizDeploy, access map[string]any) string {
	email, _ := access["email"].(string)
	target, _ := cfg.ProviderConfig["target"].(string)
	host, _ := cfg.ProviderConfig["domain"].(string)
	if cfg.ProviderAccessId == "" || email == "" || target == "" {
		return ""
	}
	binding, _ := json.Marshal([]string{cfg.Provider, cfg.ProviderAccessId, strings.TrimSpace(email), target, host})
	digest := sha256.Sum256(binding)
	return hex.EncodeToString(digest[:])
}

func previousQzyunDocumentID(output *domain.WorkflowOutput, binding string) string {
	if output == nil || !output.Succeeded || binding == "" {
		return ""
	}
	for _, item := range output.Outputs {
		if item == nil || item.Name != "qzyunDocument" {
			continue
		}
		scope, id, ok := strings.Cut(item.Value, "#")
		if ok && scope == binding && qzyunDocumentIDPattern.MatchString(id) {
			return id
		}
	}
	return ""
}
