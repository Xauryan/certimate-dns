package dnsmgrextra

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const kuocaiBaseURL = "https://www.kuocaicdn.com"

func (d *deployer) kuocaiRequest(ctx context.Context, path, contentType string, body *bytes.Buffer, cookie *http.Cookie) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, kuocaiBaseURL+path, body)
	if err != nil {
		return nil, errors.New("invalid Kuocai request")
	}
	req.Header.Set("Content-Type", contentType)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	res, err := d.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("Kuocai connection failed before confirmation")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Kuocai returned HTTP %d", res.StatusCode)
	}
	var reply struct {
		Code string
		Data json.RawMessage
	}
	const limit = 64 << 10
	b, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil || len(b) > limit || json.Unmarshal(b, &reply) != nil || reply.Code != "SUCCESS" {
		return nil, errors.New("Kuocai did not confirm the operation")
	}
	return reply.Data, nil
}

func (d *deployer) deployKuocai(ctx context.Context, cert, key string) error {
	login := url.Values{"userAccount": {d.username}, "userPwd": {d.password}, "remember": {"true"}}
	data, err := d.kuocaiRequest(ctx, "/login/loginUser", "application/x-www-form-urlencoded", bytes.NewBufferString(login.Encode()), nil)
	if err != nil {
		return fmt.Errorf("Kuocai login: %w", err)
	}
	var token string
	if json.Unmarshal(data, &token) != nil || token == "" {
		return errors.New("Kuocai login did not issue a session")
	}
	cookie := &http.Cookie{Name: "kuocai_cdn_token", Value: token}
	if cookie.Valid() != nil {
		return errors.New("Kuocai returned an invalid session token")
	}
	hash := sha256.Sum256([]byte(cert))
	payload := map[string]any{"doMainId": d.target, "https": map[string]string{
		"certificate_name": "cert_" + hex.EncodeToString(hash[:8]), "certificate_source": "0", "certificate_value": cert, "https_status": "on", "private_key": key,
	}}
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(payload); err != nil {
		return errors.New("failed to encode Kuocai certificate")
	}
	_, err = d.kuocaiRequest(ctx, "/CdnDomainHttps/httpsConfiguration", "application/json", &b, cookie)
	return err
}
