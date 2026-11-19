package deployers

import (
	"errors"

	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/pkg/core"
	tcssl "github.com/certimate-go/certimate/pkg/core/deployer/providers/tencentcloud-ssl-deploy"
	xmaps "github.com/certimate-go/certimate/pkg/utils/maps"
)

func init() {
	Registries.MustRegister(domain.DeploymentProviderTypeTencentCloudLighthouse, tencentDomainFactory(tcssl.NewLighthouseDeployer, "instanceId"))
	Registries.MustRegister(domain.DeploymentProviderTypeTencentCloudTCB, tencentDomainFactory(tcssl.NewCloudBaseDeployer, "environmentId"))
}

func tencentDomainFactory(newProvider func(tcssl.DomainDeployerConfig, string) (core.Deployer, error), resourceField string) ProviderFactoryFunc {
	return func(options *ProviderFactoryOptions) (core.Deployer, error) {
		var credentials domain.AccessConfigForTencentCloud
		if err := xmaps.Populate(options.ProviderAccessConfig, &credentials); err != nil {
			return nil, errors.New("invalid Tencent Cloud access configuration")
		}
		return newProvider(tcssl.DomainDeployerConfig{
			SecretId: credentials.SecretId, SecretKey: credentials.SecretKey, ProjectId: credentials.ProjectId,
			Region: xmaps.GetString(options.ProviderExtendedConfig, "region"),
			Domain: xmaps.GetString(options.ProviderExtendedConfig, "domain"),
		}, xmaps.GetString(options.ProviderExtendedConfig, resourceField))
	}
}
