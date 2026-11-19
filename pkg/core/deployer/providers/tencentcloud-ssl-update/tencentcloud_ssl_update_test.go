package tencentcloudsslupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestCertificateReplacementKeepsMaterialOutOfDiagnostics(t *testing.T) {
	const certificate = "synthetic-certificate"
	const privateKey = "synthetic-private-key"
	const providerEcho = "synthetic-provider-echo"
	for _, tt := range []struct {
		name     string
		submit   string
		poll     string
		wantFail bool
	}{
		{
			name:   "confirmed",
			submit: `{"DeployStatus":1,"DeployRecordId":27,"RequestId":"` + providerEcho + `"}`,
			poll:   `{"DeployRecordDetail":[{"TotalCount":1,"SuccessTotalCount":1}],"RequestId":"` + providerEcho + `"}`,
		},
		{
			name:     "provider error at submission",
			submit:   `{"Error":{"Code":"InternalError","Message":"` + providerEcho + `"}}`,
			wantFail: true,
		},
		{
			name:     "provider error at readback",
			submit:   `{"DeployStatus":1,"DeployRecordId":27}`,
			poll:     `{"Error":{"Code":"InternalError","Message":"` + providerEcho + `"}}`,
			wantFail: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewDeployer(&DeployerConfig{
				SecretId: "test-id", SecretKey: "test-secret", CertificateId: "certificate-1",
				ResourceProducts: []string{"cdn"}, IsReplaced: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			d.pollInterval = time.Millisecond
			var logs bytes.Buffer
			d.SetLogger(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
			submissions, readbacks := 0, 0
			d.sdkClient.WithHttpTransport(roundTrip(func(req *http.Request) (*http.Response, error) {
				var response string
				switch req.Header.Get("X-TC-Action") {
				case "UploadUpdateCertificateInstance":
					submissions++
					var body struct {
						CertificatePublicKey, CertificatePrivateKey, OldCertificateId string
					}
					if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
						return nil, err
					}
					if body.CertificatePrivateKey != privateKey || body.CertificatePublicKey != certificate || body.OldCertificateId != "certificate-1" {
						t.Error("unexpected certificate replacement request")
					}
					response = tt.submit
				case "DescribeHostUploadUpdateRecordDetail":
					readbacks++
					response = tt.poll
				default:
					t.Fatal("unexpected SDK action")
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"Response":` + response + `}`))}, nil
			}))
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result, err := d.Deploy(ctx, certificate, privateKey)
			if (err != nil) != tt.wantFail || (result == nil) != tt.wantFail {
				t.Fatal("unexpected deployment result")
			}
			if submissions != 1 || (readbacks == 1) != (tt.poll != "") {
				t.Fatalf("unexpected API call counts: %d submissions, %d readbacks", submissions, readbacks)
			}
			diagnostics := logs.String()
			if err != nil {
				diagnostics += err.Error()
			}
			for _, sensitive := range []string{certificate, privateKey, providerEcho} {
				if strings.Contains(diagnostics, sensitive) {
					t.Error("sensitive material leaked into deployment diagnostics")
				}
			}
		})
	}
}
