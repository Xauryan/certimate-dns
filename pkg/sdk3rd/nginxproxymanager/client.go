// A simple SDK client for NginxProxyManager.
// API documentation: https://github.com/NginxProxyManager/nginx-proxy-manager/discussions/3265
package nginxproxymanager

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"

	"github.com/certimate-go/certimate/internal/app"
)

type Client struct {
	username string
	password string

	token   string
	tokenMu sync.Mutex

	rc *resty.Client
}

func NewClient(serverUrl string, optFns ...OptionsFunc) (*Client, error) {
	opts := &Options{}
	for _, fn := range optFns {
		fn(opts)
	}

	if serverUrl == "" {
		return nil, fmt.Errorf("sdkerr: unset serverUrl")
	}
	u, err := url.Parse(serverUrl)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("sdkerr: invalid serverUrl")
	}
	if opts.JwtToken == "" && (opts.Username == "" || opts.Password == "") {
		return nil, fmt.Errorf("sdkerr: unset jwtToken or username/password")
	}
	if opts.JwtToken != "" && (opts.Username != "" || opts.Password != "") {
		return nil, fmt.Errorf("sdkerr: cannot set both jwtToken and username/password")
	}

	client := &Client{
		username: opts.Username,
		password: opts.Password,
		token:    opts.JwtToken,
	}
	client.rc = resty.New().
		SetBaseURL(strings.TrimSuffix(serverUrl, "/")+"/api").
		SetHeader("Accept", "application/json").
		SetHeader("Content-Type", "application/json").
		SetHeader("User-Agent", app.AppUserAgent).
		SetPreRequestHook(func(_ *resty.Client, req *http.Request) error {
			if client.token != "" {
				req.Header.Set("Authorization", "Bearer "+client.token)
			}

			return nil
		})

	// Credentials and multipart certificate files belong to this API endpoint.
	client.rc.GetClient().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client, nil
}

func (c *Client) SetTimeout(timeout time.Duration) *Client {
	c.rc.SetTimeout(timeout)
	return c
}

func (c *Client) SetTLSConfig(config *tls.Config) *Client {
	c.rc.SetTLSClientConfig(config)
	return c
}

func (c *Client) newRequest(method string, path string) (*resty.Request, error) {
	if method == "" {
		return nil, fmt.Errorf("sdkerr: unset method")
	}
	if path == "" {
		return nil, fmt.Errorf("sdkerr: unset path")
	}

	req := c.rc.R()
	req.Method = method
	req.URL = path

	// WARN:
	//   DO NOT CALL `req.SetResult` or `req.SetError` AGAIN! USE `doRequestWithResult` INSTEAD.
	return req, nil
}

func (c *Client) doRequest(req *resty.Request) (*resty.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("sdkerr: nil request")
	}

	resp, err := req.Send()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return resp, context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return resp, context.DeadlineExceeded
		}
		return resp, fmt.Errorf("sdkerr: request failed before confirmation")
	} else if !resp.IsSuccess() {
		return resp, fmt.Errorf("sdkerr: unexpected HTTP status %d", resp.StatusCode())
	}

	return resp, nil
}

func (c *Client) doRequestWithResult(req *resty.Request, res any) (*resty.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("sdkerr: nil request")
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return resp, err
	}
	body := bytes.TrimSpace(resp.Body())
	if len(body) == 0 {
		if req.Method == http.MethodGet {
			return resp, fmt.Errorf("sdkerr: empty response to lookup")
		}
		return resp, nil
	}
	if bytes.Equal(body, []byte("null")) {
		return resp, fmt.Errorf("sdkerr: unexpected null response")
	}
	var envelope sdkResponseBase
	if json.Unmarshal(body, &envelope) == nil && envelope.hasError() {
		return resp, fmt.Errorf("sdkerr: NPM returned an API error")
	}
	if err := json.Unmarshal(body, res); err != nil {
		return resp, fmt.Errorf("sdkerr: invalid response format")
	}

	return resp, nil
}

func (c *Client) ensureToken(ctx context.Context) error {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.token != "" {
		return nil
	}

	httpreq, err := c.newRequest(http.MethodPost, "/tokens")
	if err != nil {
		return err
	} else {
		httpreq.SetBody(map[string]string{
			"identity": c.username,
			"secret":   c.password,
		})
		httpreq.SetContext(ctx)
	}

	type tokensResponse struct {
		sdkResponseBase
		Token   string `json:"token"`
		Expires string `json:"expires"`
	}

	result := &tokensResponse{}
	if _, err := c.doRequestWithResult(httpreq, result); err != nil {
		return err
	}
	if result.Token == "" {
		return fmt.Errorf("sdkerr: auth error: received empty token")
	}
	c.token = result.Token

	return nil
}
