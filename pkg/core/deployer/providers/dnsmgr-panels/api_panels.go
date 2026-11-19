package dnsmgrpanels

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

func (p *panel) deployDirectAdmin(ctx context.Context, cert, key string, parsedKey any) error {
	if ec, ok := parsedKey.(*ecdsa.PrivateKey); ok && strings.HasPrefix(strings.TrimSpace(key), "-----BEGIN PRIVATE KEY-----") {
		b, err := x509.MarshalECPrivateKey(ec)
		if err != nil {
			return errors.New("unable to convert EC private key to SEC1")
		}
		key = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))
	}
	bundle := strings.TrimSpace(key) + "\n" + strings.TrimSpace(cert) + "\n"
	return forTargets(p.targets, func(target string) error {
		res, err := p.call(ctx, "/CMD_API_SSL", nil, url.Values{"action": {"save"}, "type": {"paste"}, "domain": {target}, "certificate": {bundle}}, "")
		if err != nil {
			return err
		}
		if res.status != http.StatusOK {
			return errors.New("DirectAdmin certificate installation failed")
		}
		if strings.HasPrefix(strings.TrimSpace(res.body), "{") {
			var result struct {
				Error json.RawMessage `json:"error"`
			}
			if json.Unmarshal([]byte(res.body), &result) == nil {
				switch string(result.Error) {
				case `"0"`, "0", "false":
					return nil
				}
			}
		} else if v, err := url.ParseQuery(res.body); err == nil && len(v["error"]) == 1 && v.Get("error") == "0" {
			return nil
		}
		return errors.New("DirectAdmin did not confirm certificate installation")
	})
}
