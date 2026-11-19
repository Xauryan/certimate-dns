package engine

import (
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
)

func TestQzyunDocumentReceiptRemainsScoped(t *testing.T) {
	config := domain.WorkflowNodeConfigForBizDeploy{Provider: "qzyun", ProviderAccessId: "original", ProviderConfig: map[string]any{"target": "customer", "domain": "a.example.test"}}
	account := map[string]any{"email": "first@example.test", "password": "synthetic"}
	scope := qzyunBindingHash(config, account)
	const id = "0123456789abcdefghijklmn"
	output := &domain.WorkflowOutput{Succeeded: true, Outputs: []*domain.WorkflowOutputEntry{{Name: "qzyunDocument", Value: scope + "#" + id}}}
	if previousQzyunDocumentID(output, scope) != id {
		t.Fatal("matching receipt missing")
	}
	account["password"] = "rotated synthetic"
	if previousQzyunDocumentID(output, qzyunBindingHash(config, account)) != id {
		t.Fatal("same tenant after password change lost receipt")
	}
	for _, test := range []struct{ key, value string }{
		{"access", "other"}, {"email", "second@example.test"}, {"target", "other"}, {"domain", "other.example.test"}, {"provider", "other"},
	} {
		cfg := config
		cfg.ProviderConfig = map[string]any{"target": "customer", "domain": "a.example.test"}
		creds := map[string]any{"email": account["email"]}
		switch test.key {
		case "access":
			cfg.ProviderAccessId = test.value
		case "provider":
			cfg.Provider = test.value
		case "email":
			creds["email"] = test.value
		default:
			cfg.ProviderConfig[test.key] = test.value
		}
		if previousQzyunDocumentID(output, qzyunBindingHash(cfg, creds)) != "" {
			t.Fatalf("reused after changing %s", test.key)
		}
	}
	output.Succeeded = false
	if previousQzyunDocumentID(output, scope) != "" {
		t.Fatal("reused ID from failure")
	}
	output.Succeeded = true
	output.Outputs[0].Value = scope + "#invalid"
	if previousQzyunDocumentID(output, scope) != "" {
		t.Fatal("reused invalid ID")
	}
}
