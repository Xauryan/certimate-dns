package dnsmcp

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	xcert "github.com/certimate-go/certimate/pkg/utils/cert"
)

func TestGoogleIssuerAccountModes(t *testing.T) {
	spec := issuerAccountSpecs["google"]
	inputs := certAccountInputSchemas(false)["google"]["inputs"].(object)
	if inputs["email"].(object)["required"] != true || inputs["serviceAccountKey"].(object)["description"] == nil {
		t.Fatal("Google issuer schema is missing its mode-specific fields")
	}
	if _, err := spec.configure(object{}, object{"email": "fixture@example.test"}); err != invalid {
		t.Fatal("default manual mode accepted an incomplete EAB pair")
	}
	config := object{}
	manual := object{"email": "fixture@example.test", "kid": "synthetic-legacy-id", "key": "synthetic-legacy-key"}
	if native, err := spec.configure(config, manual); err != nil || native != "googletrustservices" {
		t.Fatal("legacy manual EAB was rejected")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := xcert.ConvertRSAPrivateKeyToPEM(key, true)
	if err != nil {
		t.Fatal(err)
	}
	keyJSON, err := json.MarshalIndent(map[string]string{
		"type": "service_account", "client_email": "service@example.test", "private_key": pem,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	auto := object{"mode": "staging", "eabMode": "auto", "projectId": "fixture-project", "serviceAccountKey": string(keyJSON)}
	if native, err := spec.configure(config, auto); err != nil || native != "googletrustservices" {
		t.Fatal("automatic project EAB rejected a multiline service account credential")
	}
	if config["eabKid"] != nil || config["eabHmacKey"] != nil {
		t.Fatal("automatic mode retained the inactive manual pair")
	}
	bad := object{"email": "fixture@example.test", "eabMode": "auto", "projectId": "fixture-project", "serviceAccountKey": `{"type":"external_account"}`}
	if _, err := spec.configure(object{}, bad); err != invalid {
		t.Fatal("automatic mode accepted a credential from the wrong OAuth flow")
	}
	manual["eabMode"] = "manual"
	if _, err := spec.configure(config, manual); err != nil || config["serviceAccountKey"] != nil || config["projectId"] != nil {
		t.Fatal("manual mode failed to clear inactive project credentials")
	}
}
