package deployers

import (
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/pkg/core"
	"github.com/certimate-go/certimate/pkg/core/deployer/providers/iis"
)

func init() {
	Registries.MustRegister(domain.DeploymentProviderTypeIIS, func(options *ProviderFactoryOptions) (core.Deployer, error) {
		return iis.New(options.ProviderAccessConfig, options.ProviderExtendedConfig)
	})
}
