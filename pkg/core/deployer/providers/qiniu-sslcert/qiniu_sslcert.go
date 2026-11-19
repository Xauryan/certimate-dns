package qiniusslcert

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"

	"github.com/certimate-go/certimate/pkg/core"
	sslcert "github.com/certimate-go/certimate/pkg/core/certmgr/providers/qiniu-sslcert"
)

// Deployer uploads to the Qiniu certificate inventory. It has no domain-binding
// or cleanup operations.
type Deployer struct {
	manager core.Certmgr
}

func New(accessKey, secretKey string) (*Deployer, error) {
	manager, err := sslcert.NewCertmgr(&sslcert.CertmgrConfig{AccessKey: accessKey, SecretKey: secretKey})
	if err != nil {
		return nil, err
	}
	manager.SetLogger(nil)
	return &Deployer{manager: manager}, nil
}

func (d *Deployer) SetLogger(*slog.Logger) {}

func (d *Deployer) Deploy(ctx context.Context, cert, key string) (*core.DeployerDeployResult, error) {
	if _, err := tls.X509KeyPair([]byte(cert), []byte(key)); err != nil {
		return nil, errors.New("invalid TLS certificate or mismatched private key")
	}
	result, err := d.manager.Upload(ctx, cert, key)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil || result == nil || result.CertId == "" {
		return nil, errors.New("Qiniu did not confirm the certificate upload")
	}
	return &core.DeployerDeployResult{ExtendedData: map[string]any{"certificateId": result.CertId}}, nil
}
