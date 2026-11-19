// Package dnssign implements Certimate's request-bound DNSMgr form signature.
package dnssign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
)

// Sign authenticates the escaped request path and all form fields except the signature.
// Callers populate the UID, timestamp, sign_version and nonce before signing.
func Sign(path string, form url.Values, secret string) string {
	canonical := make(url.Values, len(form))
	for k, v := range form {
		if k != "sign" {
			canonical[k] = v
		}
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("DNSMgr-v2\nPOST\n" + path + "\n" + canonical.Encode()))
	return hex.EncodeToString(mac.Sum(nil))
}
