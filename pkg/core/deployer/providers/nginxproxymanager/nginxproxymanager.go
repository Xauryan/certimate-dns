package nginxproxymanager

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/samber/lo"

	"github.com/certimate-go/certimate/pkg/core"
	cmgrimpl "github.com/certimate-go/certimate/pkg/core/certmgr/providers/nginxproxymanager"
	npmsdk "github.com/certimate-go/certimate/pkg/sdk3rd/nginxproxymanager"
	xloop "github.com/certimate-go/certimate/pkg/utils/loop"
	xwait "github.com/certimate-go/certimate/pkg/utils/wait"
)

type (
	Provider     = core.Deployer
	DeployResult = core.DeployerDeployResult
)

type DeployerConfig struct {
	// NPM 服务地址。
	ServerUrl string `json:"serverUrl"`
	// NPM API 认证方式。
	// 可取值 "password"、"token"。
	// 零值时默认值 [AUTH_METHOD_PASSWORD]。
	AuthMethod string `json:"authMethod,omitempty"`
	// NPM 用户名。
	Username string `json:"username,omitempty"`
	// NPM 密码。
	Password string `json:"password,omitempty"`
	// NPM API Token。
	ApiToken string `json:"apiToken,omitempty"`
	// 是否允许不安全的连接。
	AllowInsecureConnections bool `json:"allowInsecureConnections,omitempty"`
	// 部署目标。
	DeployTarget string `json:"deployTarget"`
	// 域名匹配模式。
	// 零值时默认值 [HOST_MATCH_PATTERN_SPECIFIED]。
	HostMatchPattern string `json:"hostMatchPattern,omitempty"`
	// 主机类型。
	// 部署目标为 [DEPLOY_TARGET_HOST] 时必填。
	HostType string `json:"hostType,omitempty"`
	// 主机 ID。
	// 部署目标为 [DEPLOY_TARGET_HOST]、且匹配模式非 [HOST_MATCH_PATTERN_CERTSAN] 时必填。
	HostId int64 `json:"hostId,omitempty"`
	// 证书 ID。
	// 部署目标为 [DEPLOY_TARGET_CERTIFICATE] 时必填。
	CertificateId int64 `json:"certificateId,omitempty"`
}

type Deployer struct {
	config     *DeployerConfig
	logger     *slog.Logger
	sdkClient  *npmsdk.Client
	sdkCertmgr core.Certmgr
}

var _ Provider = (*Deployer)(nil)

func NewDeployer(config *DeployerConfig) (*Deployer, error) {
	if config == nil {
		return nil, fmt.Errorf("the configuration of the deployer provider is nil")
	}

	client, err := createSDKClient(config.ServerUrl, config.AuthMethod, config.Username, config.Password, config.ApiToken, config.AllowInsecureConnections)
	if err != nil {
		return nil, fmt.Errorf("could not create client: %w", err)
	}

	pcertmgr, err := cmgrimpl.NewCertmgr(&cmgrimpl.CertmgrConfig{
		ServerUrl:                config.ServerUrl,
		AuthMethod:               config.AuthMethod,
		Username:                 config.Username,
		Password:                 config.Password,
		ApiToken:                 config.ApiToken,
		AllowInsecureConnections: config.AllowInsecureConnections,
	})
	if err != nil {
		return nil, fmt.Errorf("could not create certmgr: %w", err)
	}

	return &Deployer{
		config:     config,
		logger:     slog.Default(),
		sdkClient:  client,
		sdkCertmgr: pcertmgr,
	}, nil
}

func (d *Deployer) SetLogger(logger *slog.Logger) {
	if logger == nil {
		d.logger = slog.New(slog.DiscardHandler)
	} else {
		d.logger = logger
	}

	d.sdkCertmgr.SetLogger(logger)
}

func (d *Deployer) Deploy(ctx context.Context, certPEM, privkeyPEM string) (*DeployResult, error) {
	// 根据部署目标决定业务流程
	switch d.config.DeployTarget {
	case DEPLOY_TARGET_HOST:
		if err := d.deployToHost(ctx, certPEM, privkeyPEM); err != nil {
			return nil, err
		}

	case DEPLOY_TARGET_CERTIFICATE:
		if err := d.deployToCertificate(ctx, certPEM, privkeyPEM); err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unsupported deploy target '%s'", d.config.DeployTarget)
	}

	return &DeployResult{}, nil
}

func (d *Deployer) deployToHost(ctx context.Context, certPEM, privkeyPEM string) error {
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(privkeyPEM))
	if err != nil {
		return fmt.Errorf("invalid certificate or mismatched private key")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("invalid leaf certificate")
	}

	// Resolve every target before allocating a certificate in the provider.
	hosts, err := d.resolveHosts(ctx, leaf)
	if err != nil {
		return err
	}
	upres, err := d.sdkCertmgr.Upload(ctx, certPEM, privkeyPEM)
	if err != nil {
		return fmt.Errorf("failed to upload certificate file: %w", err)
	}
	certID, err := strconv.ParseInt(upres.CertId, 10, 64)
	if err != nil || certID <= 0 {
		return fmt.Errorf("certificate upload returned an invalid certificate ID")
	}
	d.logger.Info("ssl certificate uploaded", slog.Int64("certId", certID))

	var hostIDs []int64
	for _, host := range hosts {
		if host.CertificateId != certID {
			hostIDs = append(hostIDs, host.Id)
		}
	}
	d.logger.Info("found hosts to update", slog.Int("count", len(hostIDs)))
	return xloop.ForRangeAllWithContext(ctx, hostIDs, func(ctx context.Context, hostID int64, i int) error {
		if i > 0 {
			if err := xwait.DelayWithContext(ctx, 3*time.Second); err != nil {
				return err
			}
		}
		if err := d.updateHostCertificate(ctx, d.config.HostType, hostID, certID); err != nil {
			return fmt.Errorf("updating host %d with certificate %d: %w", hostID, certID, err)
		}
		return nil
	})
}

func (d *Deployer) resolveHosts(ctx context.Context, cert *x509.Certificate) ([]*npmsdk.Host, error) {
	autoMatch := d.config.HostMatchPattern == HOST_MATCH_PATTERN_CERTSAN
	switch d.config.HostMatchPattern {
	case "", HOST_MATCH_PATTERN_SPECIFIED:
		if d.config.HostId <= 0 {
			return nil, fmt.Errorf("config `hostId` must be a positive integer")
		}
	case HOST_MATCH_PATTERN_CERTSAN:
	default:
		return nil, fmt.Errorf("unsupported host match pattern")
	}

	hosts, err := d.getAllHosts(ctx, d.config.HostType)
	if err != nil {
		return nil, err
	}
	var matched []*npmsdk.Host
	seen := make(map[int64]bool)
	for _, host := range hosts {
		if host.Id <= 0 || seen[host.Id] {
			return nil, fmt.Errorf("NPM returned invalid or duplicate host IDs")
		}
		seen[host.Id] = true
		if autoMatch {
			if len(host.DomainNames) == 0 || !lo.EveryBy(host.DomainNames, func(domain string) bool {
				return cert.VerifyHostname(domain) == nil
			}) {
				continue
			}
		} else if host.Id != d.config.HostId {
			continue
		}
		matched = append(matched, host)
	}
	if len(matched) == 0 {
		return nil, fmt.Errorf("no matching host found for the selected target")
	}
	return matched, nil
}

func (d *Deployer) deployToCertificate(ctx context.Context, certPEM, privkeyPEM string) error {
	if d.config.CertificateId <= 0 {
		return fmt.Errorf("config `certificateId` is required")
	}

	// 替换证书
	_, err := d.sdkCertmgr.Replace(ctx, strconv.FormatInt(d.config.CertificateId, 10), certPEM, privkeyPEM)
	if err != nil {
		return fmt.Errorf("failed to replace certificate file: %w", err)
	} else {
		d.logger.Info("ssl certificate replaced", slog.Int64("certId", d.config.CertificateId))
	}

	// 获取默认站点
	settingsGetDefaultSiteReq := &npmsdk.SettingsGetDefaultSiteRequest{}
	settingsGetDefaultSiteResp, err := d.sdkClient.SettingsGetDefaultSiteWithContext(ctx, settingsGetDefaultSiteReq)
	d.logger.Debug("sdk request 'settings.GetDefaultSite'")
	if err != nil {
		return fmt.Errorf("failed to execute sdk request 'settings.GetDefaultSite': %w", err)
	}

	// 更新默认站点，以触发 nginx 重启
	settingsSetDefaultSiteReq := &npmsdk.SettingsSetDefaultSiteRequest{
		Value: settingsGetDefaultSiteResp.Value,
	}
	_, err = d.sdkClient.SettingsSetDefaultSiteWithContext(ctx, settingsSetDefaultSiteReq)
	d.logger.Debug("sdk request 'settings.SetDefaultSite'")
	if err != nil {
		return fmt.Errorf("failed to execute sdk request 'settings.SetDefaultSite': %w", err)
	}

	return nil
}

func (d *Deployer) getAllHosts(ctx context.Context, cloudHostType string) ([]*npmsdk.Host, error) {
	var hosts []*npmsdk.Host
	switch cloudHostType {
	case HOST_TYPE_PROXY:
		{
			nginxListProxyHostsReq := &npmsdk.NginxListProxyHostsRequest{}
			nginxListProxyHostsResp, err := d.sdkClient.NginxListProxyHostsWithContext(ctx, nginxListProxyHostsReq)
			d.logger.Debug("sdk request 'nginx.ListProxyHosts'")
			if err != nil {
				return nil, fmt.Errorf("failed to execute sdk request 'nginx.ListProxyHosts': %w", err)
			}

			hosts = make([]*npmsdk.Host, 0, len(*nginxListProxyHostsResp))
			for _, hostItem := range *nginxListProxyHostsResp {
				if hostItem == nil {
					return nil, fmt.Errorf("NPM returned an invalid host")
				}
				hosts = append(hosts, &hostItem.Host)
			}
		}

	case HOST_TYPE_REDIRECTION:
		{
			nginxListRedirectionHostsReq := &npmsdk.NginxListRedirectionHostsRequest{}
			nginxListRedirectionHostsResp, err := d.sdkClient.NginxListRedirectionHostsWithContext(ctx, nginxListRedirectionHostsReq)
			d.logger.Debug("sdk request 'nginx.ListRedirectionHosts'")
			if err != nil {
				return nil, fmt.Errorf("failed to execute sdk request 'nginx.ListRedirectionHosts': %w", err)
			}

			hosts = make([]*npmsdk.Host, 0, len(*nginxListRedirectionHostsResp))
			for _, hostItem := range *nginxListRedirectionHostsResp {
				if hostItem == nil {
					return nil, fmt.Errorf("NPM returned an invalid host")
				}
				hosts = append(hosts, &hostItem.Host)
			}
		}

	case HOST_TYPE_STREAM:
		{
			nginxListStreamsReq := &npmsdk.NginxListStreamsRequest{}
			nginxListStreamsResp, err := d.sdkClient.NginxListStreamsWithContext(ctx, nginxListStreamsReq)
			d.logger.Debug("sdk request 'nginx.ListStreams'")
			if err != nil {
				return nil, fmt.Errorf("failed to execute sdk request 'nginx.ListStreams': %w", err)
			}

			hosts = make([]*npmsdk.Host, 0, len(*nginxListStreamsResp))
			for _, hostItem := range *nginxListStreamsResp {
				if hostItem == nil {
					return nil, fmt.Errorf("NPM returned an invalid host")
				}
				hosts = append(hosts, &hostItem.Host)
			}
		}

	case HOST_TYPE_DEAD:
		{
			nginxListDeadHostsReq := &npmsdk.NginxListDeadHostsRequest{}
			nginxListDeadHostsResp, err := d.sdkClient.NginxListDeadHostsWithContext(ctx, nginxListDeadHostsReq)
			d.logger.Debug("sdk request 'nginx.ListDeadHosts'")
			if err != nil {
				return nil, fmt.Errorf("failed to execute sdk request 'nginx.ListDeadHosts': %w", err)
			}

			hosts = make([]*npmsdk.Host, 0, len(*nginxListDeadHostsResp))
			for _, hostItem := range *nginxListDeadHostsResp {
				if hostItem == nil {
					return nil, fmt.Errorf("NPM returned an invalid host")
				}
				hosts = append(hosts, &hostItem.Host)
			}
		}

	default:
		return hosts, fmt.Errorf("unsupported host type")
	}

	return hosts, nil
}

func (d *Deployer) updateHostCertificate(ctx context.Context, cloudHostType string, cloudHostId int64, cloudCertId int64) error {
	switch cloudHostType {
	case HOST_TYPE_PROXY:
		{
			nginxUpdateProxyHostReq := &npmsdk.NginxUpdateProxyHostRequest{
				CertificateId: lo.ToPtr(cloudCertId),
			}
			_, err := d.sdkClient.NginxUpdateProxyHostWithContext(ctx, cloudHostId, nginxUpdateProxyHostReq)
			d.logger.Debug("sdk request 'nginx.UpdateProxyHost'", slog.Int64("params.hostId", cloudHostId))
			if err != nil {
				return fmt.Errorf("failed to execute sdk request 'nginx.UpdateProxyHost': %w", err)
			}
		}

	case HOST_TYPE_REDIRECTION:
		{
			nginxUpdateRedirectionHostReq := &npmsdk.NginxUpdateRedirectionHostRequest{
				CertificateId: lo.ToPtr(cloudCertId),
			}
			_, err := d.sdkClient.NginxUpdateRedirectionHostWithContext(ctx, cloudHostId, nginxUpdateRedirectionHostReq)
			d.logger.Debug("sdk request 'nginx.UpdateRedirectionHost'", slog.Int64("params.hostId", cloudHostId))
			if err != nil {
				return fmt.Errorf("failed to execute sdk request 'nginx.UpdateRedirectionHost': %w", err)
			}
		}

	case HOST_TYPE_STREAM:
		{
			nginxUpdateStreamReq := &npmsdk.NginxUpdateStreamRequest{
				CertificateId: lo.ToPtr(cloudCertId),
			}
			_, err := d.sdkClient.NginxUpdateStreamWithContext(ctx, cloudHostId, nginxUpdateStreamReq)
			d.logger.Debug("sdk request 'nginx.UpdateStream'", slog.Int64("params.hostId", cloudHostId))
			if err != nil {
				return fmt.Errorf("failed to execute sdk request 'nginx.UpdateStream': %w", err)
			}
		}

	case HOST_TYPE_DEAD:
		{
			nginxUpdateDeadHostReq := &npmsdk.NginxUpdateDeadHostRequest{
				CertificateId: lo.ToPtr(cloudCertId),
			}
			_, err := d.sdkClient.NginxUpdateDeadHostWithContext(ctx, cloudHostId, nginxUpdateDeadHostReq)
			d.logger.Debug("sdk request 'nginx.UpdateDeadHost'", slog.Int64("params.hostId", cloudHostId))
			if err != nil {
				return fmt.Errorf("failed to execute sdk request 'nginx.UpdateDeadHost': %w", err)
			}
		}

	default:
		return fmt.Errorf("unsupported host type")
	}

	return nil
}

func createSDKClient(serverUrl, authMethod, username, password, apiToken string, skipTlsVerify bool) (*npmsdk.Client, error) {
	var client *npmsdk.Client
	var err error

	switch authMethod {
	case "", AUTH_METHOD_PASSWORD:
		client, err = npmsdk.NewClient(serverUrl, npmsdk.WithLogins(username, password))
	case AUTH_METHOD_TOKEN:
		client, err = npmsdk.NewClient(serverUrl, npmsdk.WithJwtToken(apiToken))
	default:
		err = fmt.Errorf("unsupported auth method '%s'", authMethod)
	}

	if err != nil {
		return nil, err
	}

	if skipTlsVerify {
		client.SetTLSConfig(&tls.Config{InsecureSkipVerify: true})
	}

	return client, nil
}
