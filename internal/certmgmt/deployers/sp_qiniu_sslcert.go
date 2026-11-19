package deployers

import (
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/pkg/core"
	qiniusslcert "github.com/certimate-go/certimate/pkg/core/deployer/providers/qiniu-sslcert"
	xmaps "github.com/certimate-go/certimate/pkg/utils/maps"
)

func init() {
	Registries.MustRegister(domain.DeploymentProviderTypeQiniuSSLCert, func(options *ProviderFactoryOptions) (core.Deployer, error) {
		return qiniusslcert.New(xmaps.GetString(options.ProviderAccessConfig, "accessKey"), xmaps.GetString(options.ProviderAccessConfig, "secretKey"))
	})
}
