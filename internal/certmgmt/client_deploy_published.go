package certmgmt

import (
	"context"
	"log/slog"

	"github.com/certimate-go/certimate/internal/domain"
)

// DeployPublishedCertificate receives settings from a published workflow node.
// Interface requests record their own status without persisting provider output.
func DeployPublishedCertificate(ctx context.Context, cfg domain.WorkflowNodeConfigForBizDeploy, accessConfig map[string]any, certificatePEM, privateKeyPEM string) error {
	_, err := NewClient(WithLogger(slog.New(slog.DiscardHandler))).DeployCertificate(ctx, &DeployCertificateRequest{
		Provider:               domain.DeploymentProviderType(cfg.Provider),
		ProviderAccessConfig:   accessConfig,
		ProviderExtendedConfig: cfg.ProviderConfig,
		CertificatePEM:         certificatePEM,
		PrivateKeyPEM:          privateKeyPEM,
	})
	return err
}
