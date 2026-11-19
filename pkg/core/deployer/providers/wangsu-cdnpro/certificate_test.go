package wangsucdnpro

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	sdk "github.com/certimate-go/certimate/pkg/sdk3rd/wangsu/cdnpro"
)

type fakeCertificateAPI struct {
	t             *testing.T
	version       int32
	marker        string
	fingerprint   string
	production    int32
	wrongLocation bool
	rejectTask    bool
	calls         []string
}

func (f *fakeCertificateAPI) GetCertificateDetailWithContext(_ context.Context, id string) (*sdk.GetCertificateDetailResponse, error) {
	f.calls = append(f.calls, "read")
	if id != "configured-id" {
		f.t.Fatal("wrong certificate requested")
	}
	j, err := json.Marshal(map[string]any{"certificateId": id, "versionInProduction": f.production, "versions": []map[string]any{{"version": f.version, "comments": f.marker, "fingerprint": f.fingerprint}}})
	if err != nil {
		f.t.Fatal(err)
	}
	var out sdk.GetCertificateDetailResponse
	if err := json.Unmarshal(j, &out); err != nil {
		f.t.Fatal(err)
	}
	return &out, nil
}
func (f *fakeCertificateAPI) UpdateCertificateWithContext(_ context.Context, id string, in *sdk.UpdateCertificateRequest) (*sdk.UpdateCertificateResponse, error) {
	f.calls = append(f.calls, "patch")
	if id != "configured-id" || in.AutoRenew != nil || in.NewVersion == nil || in.NewVersion.Comments == nil || in.NewVersion.PrivateKey == nil || in.NewVersion.Certificate == nil {
		f.t.Fatal("wrong update")
	}
	f.marker = *in.NewVersion.Comments
	f.version++
	if f.wrongLocation {
		id = "different-id"
	}
	return &sdk.UpdateCertificateResponse{CertificateLocation: fmt.Sprintf("/cdn/certificates/%s/versions/%d", id, f.version)}, nil
}
func (f *fakeCertificateAPI) CreateDeploymentTaskWithContext(_ context.Context, in *sdk.CreateDeploymentTaskRequest) (*sdk.CreateDeploymentTaskResponse, error) {
	f.calls = append(f.calls, "publish")
	if f.rejectTask {
		return nil, errors.New("sensitive-provider-body")
	}
	a := (*in.Actions)[0]
	if *in.Target != "production" || len(*in.Actions) != 1 || *a.Action != "deploy_cert" || *a.Version != f.version || *a.CertificateId != "configured-id" || a.PropertyId != nil {
		f.t.Fatal("wrong deployment binding")
	}
	return &sdk.CreateDeploymentTaskResponse{DeploymentTaskLocation: "/cdn/deploymentTasks/task-id"}, nil
}
func (f *fakeCertificateAPI) GetDeploymentTaskDetailWithContext(_ context.Context, id string) (*sdk.GetDeploymentTaskDetailResponse, error) {
	f.calls = append(f.calls, "poll")
	if id != "task-id" {
		f.t.Fatal("wrong publication task ID")
	}
	f.production = f.version
	return &sdk.GetDeploymentTaskDetailResponse{Status: "succeeded"}, nil
}

func TestPublishCertificateByID(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	pair := srv.TLS.Certificates[0]
	srv.Close()
	der, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}))
	key := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	fp := sha256.Sum256(pair.Certificate[0])
	api := &fakeCertificateAPI{t: t, version: 1, fingerprint: hex.EncodeToString(fp[:]), rejectTask: true}
	d := CertificateDeployer{api: api, id: "configured-id", key: "synthetic"}
	if _, err := d.Deploy(context.Background(), cert, key); err == nil || err.Error() != "CDN Pro did not confirm the publication task" {
		t.Fatal("provider failure not reported safely")
	}
	if !reflect.DeepEqual(api.calls, []string{"read", "patch", "publish"}) {
		t.Fatal(api.calls)
	}
	api.rejectTask = false
	api.calls = nil
	if _, err := d.Deploy(context.Background(), cert, key); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(api.calls, []string{"read", "publish", "poll", "read"}) {
		t.Fatalf("retry duplicated version: %v", api.calls)
	}
	api.calls = nil
	if _, err := d.Deploy(context.Background(), cert, key); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(api.calls, []string{"read"}) {
		t.Fatalf("republished confirmed production version: %v", api.calls)
	}
	api.wrongLocation = true
	api.marker = ""
	api.calls = nil
	if _, err := d.Deploy(context.Background(), cert, key); err == nil || !reflect.DeepEqual(api.calls, []string{"read", "patch"}) {
		t.Fatal("published unconfirmed certificate ID")
	}
}
