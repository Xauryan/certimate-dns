package deployers

import (
	"errors"

	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/pkg/core"
	dplyimpl "github.com/certimate-go/certimate/pkg/core/deployer/providers/tencentcloud-tke"
	xmaps "github.com/certimate-go/certimate/pkg/utils/maps"
)

func init() {
	Registries.MustRegister("tencentcloud-tke", func(options *ProviderFactoryOptions) (core.Deployer, error) {
		var credentials domain.AccessConfigForTencentCloud
		if err := xmaps.Populate(options.ProviderAccessConfig, &credentials); err != nil {
			return nil, errors.New("invalid Tencent Cloud access configuration")
		}
		return dplyimpl.NewDeployer(&dplyimpl.DeployerConfig{
			SecretId: credentials.SecretId, SecretKey: credentials.SecretKey, ProjectId: credentials.ProjectId,
			Region:     xmaps.GetString(options.ProviderExtendedConfig, "region"),
			ClusterId:  xmaps.GetString(options.ProviderExtendedConfig, "clusterId"),
			Namespace:  xmaps.GetString(options.ProviderExtendedConfig, "namespace"),
			SecretName: xmaps.GetString(options.ProviderExtendedConfig, "secretName"),
		})
	})
}
