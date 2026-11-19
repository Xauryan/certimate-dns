package wangsucdnpro

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/certimate-go/certimate/pkg/core"
	sdk "github.com/certimate-go/certimate/pkg/sdk3rd/wangsu/cdnpro"
)

type certificateAPI interface {
	GetCertificateDetailWithContext(context.Context, string) (*sdk.GetCertificateDetailResponse, error)
	UpdateCertificateWithContext(context.Context, string, *sdk.UpdateCertificateRequest) (*sdk.UpdateCertificateResponse, error)
	CreateDeploymentTaskWithContext(context.Context, *sdk.CreateDeploymentTaskRequest) (*sdk.CreateDeploymentTaskResponse, error)
	GetDeploymentTaskDetailWithContext(context.Context, string) (*sdk.GetDeploymentTaskDetailResponse, error)
}

var resourceID = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)

// CertificateDeployer publishes a new version of an existing CDN Pro
// certificate to production without changing any hostname or property.
type CertificateDeployer struct {
	api certificateAPI
	id  string
	key string
}

func NewCertificateDeployer(accessKey, secret, apiKey, id string) (*CertificateDeployer, error) {
	if apiKey == "" || !resourceID.MatchString(id) {
		return nil, errors.New("CDN Pro requires an API key and existing certificate ID")
	}
	client, err := createSDKClient(accessKey, secret)
	if err != nil {
		return nil, err
	}
	return &CertificateDeployer{api: client, id: id, key: apiKey}, nil
}

func (d *CertificateDeployer) SetLogger(*slog.Logger) {}

func (d *CertificateDeployer) Deploy(ctx context.Context, cert, key string) (*core.DeployerDeployResult, error) {
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		return nil, errors.New("invalid TLS certificate or mismatched private key")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, errors.New("invalid TLS certificate")
	}
	hash := sha256.New()
	for _, der := range pair.Certificate {
		hash.Write(der)
	}
	marker := "certimate-sha256-" + hex.EncodeToString(hash.Sum(nil))
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	info, err := d.api.GetCertificateDetailWithContext(ctx, d.id)
	if err != nil || info == nil || info.CertificateID != d.id {
		return nil, errors.New("could not confirm the selected CDN Pro certificate")
	}

	sha1DER := sha1.Sum(leaf.Raw) // CDN Pro may identify a version by its SHA-1 fingerprint.
	sha256DER := sha256.Sum256(leaf.Raw)
	var version int32
	for _, item := range info.Versions {
		fingerprint := strings.ToLower(strings.ReplaceAll(item.Fingerprint, ":", ""))
		if item.Comments == marker && item.Version > 0 && (fingerprint == hex.EncodeToString(sha1DER[:]) || fingerprint == hex.EncodeToString(sha256DER[:])) {
			if item.Version == info.VersionInProduction {
				return &core.DeployerDeployResult{}, nil
			}
			version = max(version, item.Version)
		}
	}
	if version == 0 {
		name := fmt.Sprintf("%s-%d", strings.TrimPrefix(leaf.Subject.CommonName, "*."), leaf.NotBefore.Unix())
		stamp := time.Now().Unix()
		encrypted, err := encryptPrivateKey(key, d.key, stamp)
		if err != nil {
			return nil, errors.New("could not encrypt the certificate private key")
		}
		update, err := d.api.UpdateCertificateWithContext(ctx, d.id, &sdk.UpdateCertificateRequest{
			Timestamp: stamp, Name: &name,
			NewVersion: &sdk.CertificateVersion{Certificate: &cert, PrivateKey: &encrypted, Comments: &marker},
		})
		if err != nil || update == nil {
			return nil, errors.New("CDN Pro did not confirm the certificate update")
		}
		location, err := url.Parse(update.CertificateLocation)
		prefix := "/cdn/certificates/" + d.id + "/versions/"
		if err != nil || !strings.HasPrefix(location.EscapedPath(), prefix) {
			return nil, errors.New("unexpected CDN Pro certificate version location")
		}
		n, err := strconv.ParseInt(strings.TrimPrefix(location.EscapedPath(), prefix), 10, 32)
		if err != nil || n <= 0 {
			return nil, errors.New("invalid CDN Pro certificate version")
		}
		version = int32(n)
	}

	action, target, name := "deploy_cert", "production", "Deploy certificate "+d.id
	task, err := d.api.CreateDeploymentTaskWithContext(ctx, &sdk.CreateDeploymentTaskRequest{Name: &name, Target: &target, Actions: &[]sdk.DeploymentTaskAction{
		{Action: &action, CertificateId: &d.id, Version: &version},
	}})
	if err != nil || task == nil {
		return nil, errors.New("CDN Pro did not confirm the publication task")
	}
	u, err := url.Parse(task.DeploymentTaskLocation)
	if err != nil {
		return nil, errors.New("invalid CDN Pro deployment task location")
	}
	taskID, found := strings.CutPrefix(u.EscapedPath(), "/cdn/deploymentTasks/")
	if !found || !resourceID.MatchString(taskID) {
		return nil, errors.New("invalid CDN Pro deployment task ID")
	}
	for {
		status, err := d.api.GetDeploymentTaskDetailWithContext(ctx, taskID)
		if err != nil || status == nil {
			return nil, errors.New("could not confirm CDN Pro publication status")
		}
		if status.Status == "succeeded" {
			current, err := d.api.GetCertificateDetailWithContext(ctx, d.id)
			if err != nil || current == nil || current.CertificateID != d.id || current.VersionInProduction != version {
				return nil, errors.New("CDN Pro has not confirmed the requested production certificate version")
			}
			return &core.DeployerDeployResult{}, nil
		}
		if status.Status == "failed" || status.FinishTime != "" {
			return nil, errors.New("CDN Pro publication did not succeed")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}
}
