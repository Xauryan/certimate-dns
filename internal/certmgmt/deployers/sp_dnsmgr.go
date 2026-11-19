package deployers

import (
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/pkg/core"
	edge "github.com/certimate-go/certimate/pkg/core/deployer/providers/dnsmgr-edge"
	extra "github.com/certimate-go/certimate/pkg/core/deployer/providers/dnsmgr-extra"
	hosts "github.com/certimate-go/certimate/pkg/core/deployer/providers/dnsmgr-hosts"
	panels "github.com/certimate-go/certimate/pkg/core/deployer/providers/dnsmgr-panels"
)

func init() {
	constructors := map[domain.DeploymentProviderType]func(string, map[string]any, map[string]any) (core.Deployer, error){
		domain.DeploymentProviderTypeCloudPanel:         panels.New,
		domain.DeploymentProviderTypeDirectAdmin:        panels.New,
		domain.DeploymentProviderTypeFNOS:               extra.New,
		domain.DeploymentProviderTypeKangle:             panels.New,
		domain.DeploymentProviderTypeKangleAdmin:        panels.New,
		domain.DeploymentProviderTypeKangleAdminConsole: panels.New,
		domain.DeploymentProviderTypeKuocai:             extra.New,
		domain.DeploymentProviderTypeLucky:              edge.New,
		domain.DeploymentProviderTypeMWPanel:            hosts.New,
		domain.DeploymentProviderTypeMWPanelConsole:     hosts.New,
		domain.DeploymentProviderTypeQzyun:              extra.New,
		domain.DeploymentProviderTypeUUSEC:              edge.New,
		domain.DeploymentProviderTypeWestcnVHost:        edge.New,
		domain.DeploymentProviderTypeXP:                 edge.New,
	}
	for provider, newDeployer := range constructors {
		Registries.MustRegister(provider, func(options *ProviderFactoryOptions) (core.Deployer, error) {
			return newDeployer(provider.String(), options.ProviderAccessConfig, options.ProviderExtendedConfig)
		})
	}
}
