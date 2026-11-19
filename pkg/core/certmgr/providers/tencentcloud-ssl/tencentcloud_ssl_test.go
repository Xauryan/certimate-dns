package tencentcloudssl

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUploadPrivateMaterial(t *testing.T) {
	const testCert = "synthetic-certificate-material"
	const testKey = "synthetic-private-key-material"
	for _, tc := range []struct {
		name     string
		response string
		wantErr  bool
	}{
		{"success", `{"Response":{"CertificateId":"test-cert-id"}}`, false},
		{"upload rejected", `{"Response":{"Error":{"Code":"Test.Rejected","Message":"` + testKey + `"}}}`, true},
		{"missing upload ID", `{"Response":{}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewCertmgr(&CertmgrConfig{SecretId: "test-id", SecretKey: "test-key", ProjectId: 17})
			if err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			c.SetLogger(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
			c.sdkClient.WithHttpTransport(roundTrip(func(r *http.Request) (*http.Response, error) {
				var req struct {
					CertificatePublicKey, CertificatePrivateKey string
					Repeatable                                  *bool
					ProjectId                                   int64
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					return nil, err
				}
				if r.Header.Get("X-TC-Action") != "UploadCertificate" || req.CertificatePrivateKey != testKey || req.CertificatePublicKey != testCert || req.ProjectId != 17 || req.Repeatable == nil || *req.Repeatable {
					t.Error("invalid upload request")
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(tc.response))}, nil
			}))
			result, err := c.Upload(context.Background(), testCert, testKey)
			if (err != nil) != tc.wantErr {
				t.Fatal("unexpected upload outcome")
			}
			if err == nil && result.CertId != "test-cert-id" {
				t.Error("missing certificate ID")
			}
			output := logs.String()
			if err != nil {
				output += err.Error()
			}
			if strings.Contains(output, testKey) || strings.Contains(output, testCert) {
				t.Error("upload disclosed private material")
			}
		})
	}
}
