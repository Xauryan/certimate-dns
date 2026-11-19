// Package tencentcloudtke deploys a certificate to one TLS Secret through Tencent Cloud SSL.
package tencentcloudtke

import (
	"context"
	"crypto/tls"
	"errors"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/certimate-go/certimate/pkg/core"
	ssldeploy "github.com/certimate-go/certimate/pkg/core/deployer/providers/tencentcloud-ssl-deploy"
)

type DeployerConfig struct {
	SecretId   string
	SecretKey  string
	ProjectId  int64
	Region     string
	ClusterId  string
	Namespace  string
	SecretName string
}

func NewDeployer(config *DeployerConfig) (core.Deployer, error) {
	ssl, err := deploymentConfig(config)
	if err != nil {
		return nil, err
	}
	client, err := ssldeploy.NewDeployer(ssl)
	if err != nil {
		return nil, err
	}
	return &deployer{client}, nil
}

func deploymentConfig(config *DeployerConfig) (*ssldeploy.DeployerConfig, error) {
	if config == nil || config.SecretId == "" || config.SecretKey == "" || config.ProjectId < 0 {
		return nil, errors.New("a Tencent Cloud account with a SecretId and SecretKey is required")
	}
	if len(validation.IsDNS1123Label(config.Region)) != 0 || len(validation.IsDNS1123Label(config.ClusterId)) != 0 {
		return nil, errors.New("invalid Tencent Cloud region or cluster ID")
	}
	if len(validation.IsDNS1123Label(config.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(config.SecretName)) != 0 {
		return nil, errors.New("invalid Kubernetes namespace or Secret name")
	}
	// The SSL API requires the region in the signed request header and this
	// specific ordering of identifiers in InstanceIdList.
	return &ssldeploy.DeployerConfig{
		SecretId: config.SecretId, SecretKey: config.SecretKey, ProjectId: config.ProjectId,
		ResourceRegion: config.Region, ResourceProduct: "tke",
		ResourceIds: []string{config.ClusterId + "|" + config.Namespace + "|" + config.SecretName},
	}, nil
}

type deployer struct {
	core.Deployer
}

func (d *deployer) Deploy(ctx context.Context, certPEM, privateKeyPEM string) (*core.DeployerDeployResult, error) {
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(privateKeyPEM)); err != nil {
		return nil, errors.New("invalid certificate or mismatched private key")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	return d.Deployer.Deploy(ctx, certPEM, privateKeyPEM)
}
