package certmgmt

import (
	"context"
	"errors"
	"log/slog"

	"github.com/certimate-go/certimate/internal/certmgmt/deployers"
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/pkg/core"
)

type DeployCertificateRequest struct {
	// 提供商相关
	Provider               domain.DeploymentProviderType
	ProviderAccessConfig   map[string]any
	ProviderExtendedConfig map[string]any

	// 证书相关
	CertificatePEM string
	PrivateKeyPEM  string
}

type DeployCertificateResponse = core.DeployerDeployResult

func (c *Client) DeployCertificate(ctx context.Context, request *DeployCertificateRequest) (*DeployCertificateResponse, error) {
	if request == nil {
		return nil, errors.New("the request is nil")
	}

	providerFactory, err := deployers.Registries.Get(request.Provider)
	if err != nil {
		return nil, err
	}

	providerLog := newDeploymentLog(c.logger)
	provider, err := providerFactory(&deployers.ProviderFactoryOptions{
		ProviderAccessConfig:   request.ProviderAccessConfig,
		ProviderExtendedConfig: request.ProviderExtendedConfig,
	})
	if err != nil {
		return nil, deploymentError(err, "could not initialize the selected deployment provider; verify its credentials and target settings")
	}

	provider.SetLogger(slog.New(providerLog))
	result, err := provider.Deploy(ctx, request.CertificatePEM, request.PrivateKeyPEM)
	if err != nil {
		return nil, deploymentError(err, "certificate deployment failed; check the selected remote target before retrying")
	}

	if result == nil {
		result = &DeployCertificateResponse{}
	}
	return result, nil
}
