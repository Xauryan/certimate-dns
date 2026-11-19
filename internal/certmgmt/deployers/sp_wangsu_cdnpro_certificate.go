package deployers

import (
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/pkg/core"
	cdnpro "github.com/certimate-go/certimate/pkg/core/deployer/providers/wangsu-cdnpro"
	xmaps "github.com/certimate-go/certimate/pkg/utils/maps"
)

func init() {
	Registries.MustRegister(domain.DeploymentProviderTypeWangsuCDNProCertificate, func(options *ProviderFactoryOptions) (core.Deployer, error) {
		creds := options.ProviderAccessConfig
		return cdnpro.NewCertificateDeployer(xmaps.GetString(creds, "accessKeyId"), xmaps.GetString(creds, "accessKeySecret"), xmaps.GetString(creds, "apiKey"), xmaps.GetString(options.ProviderExtendedConfig, "certificateId"))
	})
}
