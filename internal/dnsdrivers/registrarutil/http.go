// Package registrarutil handles bounded, credential-safe registrar responses.
package registrarutil

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
)

type API struct {
	Base    string
	Client  *http.Client
	Headers http.Header
}

func (a *API) Do(ctx context.Context, method, path, contentType string, payload io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, a.Base+path, payload)
	if err != nil {
		return nil, errors.New("invalid DNS provider request")
	}
	req.Header = a.Headers.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return dnsutil.ReadResponse(a.Client, req)
}

func (a *API) JSON(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	var contentType string
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return errors.New("invalid DNS provider request")
		}
		body = bytes.NewReader(data)
		contentType = "application/json"
	}
	data, err := a.Do(ctx, method, path, contentType, body)
	if err != nil {
		return err
	}
	if output != nil && json.Unmarshal(data, output) != nil {
		return errors.New("invalid DNS provider response")
	}
	return nil
}
