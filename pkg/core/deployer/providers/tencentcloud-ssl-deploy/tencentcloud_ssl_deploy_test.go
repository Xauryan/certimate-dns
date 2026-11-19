package tencentcloudssldeploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/certimate-go/certimate/pkg/core"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type fakeInventory struct {
	core.Certmgr
	uploads int
}

func (s *fakeInventory) Upload(context.Context, string, string) (*core.CertmgrUploadResult, error) {
	s.uploads++
	return &core.CertmgrUploadResult{CertId: "test-cert"}, nil
}

func TestTKEDeployRecord(t *testing.T) {
	const cert, key = "synthetic-certificate", "synthetic-private-key"
	for _, tc := range []struct {
		name              string
		submit            string
		polls             []string
		wantError, cancel bool
	}{
		{name: "await confirmed deployment", polls: []string{`{"TotalCount":0}`, `{"TotalCount":1,"RunningTotalCount":1}`, `{"TotalCount":1,"SuccessTotalCount":1}`}},
		{name: "existing task", submit: `{"DeployRecordId":27,"DeployStatus":0}`, wantError: true},
		{name: "failed task", polls: []string{`{"TotalCount":1,"FailedTotalCount":1,"DeployRecordDetailList":[{"ErrorMsg":"sensitive-provider-message"}]}`}, wantError: true},
		{name: "missing counts", polls: []string{`{}`}, wantError: true},
		{name: "canceled waiting for remote", polls: []string{`{"TotalCount":1,"PendingTotalCount":1}`}, wantError: true, cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			d, err := NewDeployer(&DeployerConfig{SecretId: "test-id", SecretKey: "test-secret", ResourceRegion: "ap-guangzhou", ResourceProduct: "tke", ResourceIds: []string{"cls-test|apps|api.tls"}})
			if err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			d.SetLogger(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
			inventory := &fakeInventory{}
			d.sdkCertmgr = inventory
			d.pollInterval = time.Millisecond
			queries, submits := 0, 0
			d.sdkClient.WithHttpTransport(roundTrip(func(r *http.Request) (*http.Response, error) {
				var req map[string]any
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					return nil, err
				}
				var reply string
				if r.Header.Get("X-TC-Region") != "ap-guangzhou" {
					t.Error("missing region on SSL API request")
				}
				switch r.Header.Get("X-TC-Action") {
				case "DeployCertificateInstance":
					submits++
					ids, ok := req["InstanceIdList"].([]any)
					if req["ResourceType"] != "tke" || req["CertificateId"] != "test-cert" || req["Status"] != nil || !ok || len(ids) != 1 || ids[0] != "cls-test|apps|api.tls" {
						t.Error("incorrect TKE submission")
					}
					reply = `{"DeployRecordId":27,"DeployStatus":1}`
					if tc.submit != "" {
						reply = tc.submit
					}
				case "DescribeHostDeployRecordDetail":
					if req["DeployRecordId"] != "27" || queries >= len(tc.polls) {
						t.Fatal("unexpected poll")
					}
					reply = tc.polls[queries]
					queries++
					if tc.cancel {
						cancel()
					}
				default:
					t.Fatal("unexpected SDK action")
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"Response":` + reply + `}`))}, nil
			}))
			result, err := d.Deploy(ctx, cert, key)
			if (err != nil) != tc.wantError || tc.cancel && !errors.Is(err, context.Canceled) || queries != len(tc.polls) || submits != 1 || inventory.uploads != 1 {
				t.Fatalf("unexpected outcome. polls=%d submissions=%d err=%v", queries, submits, err)
			}
			if err == nil && result.ExtendedData["deployRecordId"] != "27" {
				t.Error("missing remote record")
			}
			if strings.Contains(logs.String(), key) || strings.Contains(logs.String(), "sensitive-provider-message") {
				t.Error("sensitive material logged")
			}
		})
	}
}
