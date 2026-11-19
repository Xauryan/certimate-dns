package tencentcloudssldeploy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/samber/lo"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/certimate-go/certimate/pkg/core"
	tcssl "github.com/certimate-go/certimate/pkg/sdk3rd-trimmed/github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
	"github.com/certimate-go/certimate/pkg/utils/cert/hostname"
)

type DomainDeployerConfig struct {
	SecretId  string
	SecretKey string
	ProjectId int64
	Region    string
	Domain    string
}

const cloudBaseAccessService = "AccessService"

// NewLighthouseDeployer binds one domain on a selected Lighthouse instance.
func NewLighthouseDeployer(config DomainDeployerConfig, instanceID string) (core.Deployer, error) {
	if !strings.HasPrefix(instanceID, "lhins-") || len(validation.IsDNS1123Label(instanceID)) != 0 {
		return nil, errors.New("invalid Lighthouse instance ID")
	}
	return newDomainDeployer(config, "lighthouse", instanceID)
}

// NewCloudBaseDeployer binds one CloudBase AccessService custom hostname.
func NewCloudBaseDeployer(config DomainDeployerConfig, environmentID string) (core.Deployer, error) {
	if len(validation.IsDNS1123Label(environmentID)) != 0 {
		return nil, errors.New("invalid CloudBase environment ID")
	}
	return newDomainDeployer(config, "tcb", environmentID)
}

type domainDeployer struct {
	*Deployer
	domain string
}

func newDomainDeployer(config DomainDeployerConfig, product, resourceID string) (*domainDeployer, error) {
	if config.SecretId == "" || config.SecretKey == "" || config.ProjectId < 0 {
		return nil, errors.New("invalid Tencent Cloud credentials")
	}
	if len(validation.IsDNS1123Label(config.Region)) != 0 {
		return nil, errors.New("invalid Tencent Cloud region")
	}
	domain := strings.ToLower(strings.TrimSuffix(config.Domain, "."))
	if !strings.Contains(domain, ".") || !hostname.IsDNSName(domain) || net.ParseIP(domain) != nil {
		return nil, errors.New("a valid custom DNS hostname is required")
	}

	// https://cloud.tencent.com/document/product/400/91667
	instance := config.Region + "|" + resourceID + "|" + domain
	if product == "tcb" {
		instance = cloudBaseAccessService + "|" + instance
	}
	d, err := NewDeployer(&DeployerConfig{
		SecretId: config.SecretId, SecretKey: config.SecretKey, ProjectId: config.ProjectId,
		ResourceRegion: config.Region, ResourceProduct: product, ResourceIds: []string{instance},
	})
	if err != nil {
		return nil, err
	}
	d.confirmTarget = func(detail *tcssl.DescribeHostDeployRecordDetailResponse, certID string) bool {
		for _, row := range detail.Response.DeployRecordDetailList {
			if row == nil || lo.FromPtr(row.CertId) != certID || lo.FromPtr(row.Status) != 1 ||
				!slices.ContainsFunc(row.Domains, func(v *string) bool { return strings.EqualFold(lo.FromPtr(v), domain) }) {
				continue
			}
			if product == "lighthouse" && lo.FromPtr(row.InstanceId) == resourceID {
				return true
			}
			if product == "tcb" && lo.FromPtr(row.EnvId) == resourceID && lo.FromPtr(row.TCBType) == cloudBaseAccessService && lo.FromPtr(row.Region) == config.Region {
				return true
			}
		}
		return false
	}
	return &domainDeployer{Deployer: d, domain: domain}, nil
}

func (d *domainDeployer) Deploy(ctx context.Context, certificate, privateKey string) (*core.DeployerDeployResult, error) {
	pair, err := tls.X509KeyPair([]byte(certificate), []byte(privateKey))
	if err != nil {
		return nil, errors.New("invalid certificate or mismatched private key")
	}
	leaf := pair.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, errors.New("invalid TLS certificate")
		}
	}
	now := time.Now()
	if leaf.IsCA || leaf.VerifyHostname(d.domain) != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("certificate is invalid for the selected hostname and time")
	}
	if len(leaf.ExtKeyUsage)+len(leaf.UnknownExtKeyUsage) > 0 &&
		!slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return nil, errors.New("certificate does not allow TLS server authentication")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	return d.Deployer.Deploy(ctx, certificate, privateKey)
}
