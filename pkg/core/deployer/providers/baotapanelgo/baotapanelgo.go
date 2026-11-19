package baotapanelgo

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/samber/lo"

	"github.com/certimate-go/certimate/internal/iisbind"
	"github.com/certimate-go/certimate/pkg/core"
	btpanelgosdk "github.com/certimate-go/certimate/pkg/sdk3rd/btpanelgo"
	xcert "github.com/certimate-go/certimate/pkg/utils/cert"
	xloop "github.com/certimate-go/certimate/pkg/utils/loop"
	xwait "github.com/certimate-go/certimate/pkg/utils/wait"
)

type (
	Provider     = core.Deployer
	DeployResult = core.DeployerDeployResult
)

type DeployerConfig struct {
	// 宝塔面板服务地址。
	ServerUrl string `json:"serverUrl"`
	// 宝塔面板接口密钥。
	ApiKey string `json:"apiKey"`
	// 是否允许不安全的连接。
	AllowInsecureConnections bool `json:"allowInsecureConnections,omitempty"`
	// 网站类型。
	SiteType string `json:"siteType"`
	// 网站名称。
	SiteNames []string `json:"siteNames,omitempty"`
}

type Deployer struct {
	config    *DeployerConfig
	logger    *slog.Logger
	sdkClient *btpanelgosdk.Client
}

var _ Provider = (*Deployer)(nil)

var (
	btProjectTypes      = []string{"php", "java", "asp", "go", "python", "nodejs", "proxy", "general"}
	btProjectTypesInIIS = []string{"php", "asp", "aspx"}
)

func NewDeployer(config *DeployerConfig) (*Deployer, error) {
	if config == nil {
		return nil, fmt.Errorf("the configuration of the deployer provider is nil")
	}

	client, err := createSDKClient(config.ServerUrl, config.ApiKey, config.AllowInsecureConnections)
	if err != nil {
		return nil, fmt.Errorf("could not create client: %w", err)
	}

	return &Deployer{
		config:    config,
		logger:    slog.Default(),
		sdkClient: client,
	}, nil
}

func (d *Deployer) SetLogger(logger *slog.Logger) {
	if logger == nil {
		d.logger = slog.New(slog.DiscardHandler)
	} else {
		d.logger = logger
	}
}

func (d *Deployer) Deploy(ctx context.Context, certPEM, privkeyPEM string) (*DeployResult, error) {
	if len(d.config.SiteNames) == 0 {
		return nil, fmt.Errorf("config `siteNames` is required")
	}

	if d.config.SiteType == "iis-domain" {
		if err := d.deployIISDomains(ctx, certPEM, privkeyPEM); err != nil {
			return nil, err
		}
		return &DeployResult{}, nil
	}
	if d.config.SiteType != "" {
		if !lo.Contains(btProjectTypes, d.config.SiteType) && !lo.Contains(btProjectTypesInIIS, d.config.SiteType) {
			return nil, fmt.Errorf("unsupported site type: '%s'", d.config.SiteType)
		}
	}

	// 批量更新站点证书
	if err := xloop.ForRangeAllWithContext(ctx, d.config.SiteNames, func(ctx context.Context, siteName string, i int) error {
		if i > 0 {
			if err := xwait.DelayWithContext(ctx, 3*time.Second); err != nil {
				return err
			}
		}

		return d.updateSiteCertificate(ctx, d.config.SiteType, siteName, certPEM, privkeyPEM)
	}); err != nil {
		return nil, err
	}

	return &DeployResult{}, nil
}

func (d *Deployer) findSiteByName(ctx context.Context, siteType, siteName string) (*btpanelgosdk.SiteData, error) {
	if siteType == "" || lo.Contains(btProjectTypesInIIS, siteType) {
		// 查询网站列表
		datalistGetDataListPage := 1
		datalistGetDataListLimit := 10
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			datalistGetDataListReq := &btpanelgosdk.DatalistGetDataListRequest{
				Table:        lo.ToPtr("sites"),
				SearchString: lo.ToPtr(siteName),
				Page:         lo.ToPtr(int32(datalistGetDataListPage)),
				Limit:        lo.ToPtr(int32(datalistGetDataListLimit)),
			}
			datalistGetDataListResp, err := d.sdkClient.DatalistGetDataListWithContext(ctx, datalistGetDataListReq)
			d.logger.Debug("sdk request 'datalist.GetDataList'")
			if err != nil {
				return nil, fmt.Errorf("failed to execute sdk request 'datalist.GetDataList': %w", err)
			}

			for _, siteItem := range datalistGetDataListResp.Data {
				if strings.EqualFold(siteItem.Name, siteName) {
					return siteItem, nil
				}
			}

			if len(datalistGetDataListResp.Data) < datalistGetDataListLimit {
				break
			}

			datalistGetDataListPage++
		}
	} else {
		// 查询网站列表
		siteGetProjectListPage := 1
		siteGetProjectListLimit := 10
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			siteGetProjectListReq := &btpanelgosdk.SiteGetProjectListRequest{
				SearchType:   lo.ToPtr(siteType),
				SearchString: lo.ToPtr(siteName),
				Page:         lo.ToPtr(int32(siteGetProjectListPage)),
				Limit:        lo.ToPtr(int32(siteGetProjectListLimit)),
			}
			siteGetProjectListResp, err := d.sdkClient.SiteGetProjectListWithContext(ctx, siteGetProjectListReq)
			d.logger.Debug("sdk request 'site.GetProjectList'")
			if err != nil {
				return nil, fmt.Errorf("failed to execute sdk request 'site.GetProjectList': %w", err)
			}

			for _, siteItem := range siteGetProjectListResp.Data {
				if strings.EqualFold(siteItem.Name, siteName) {
					return siteItem, nil
				}
			}

			if len(siteGetProjectListResp.Data) < siteGetProjectListLimit {
				break
			}

			siteGetProjectListPage++
		}
	}

	return nil, fmt.Errorf("could not find site '%s'", siteName)
}

func (d *Deployer) updateSiteCertificate(ctx context.Context, siteType, siteName string, certPEM, privkeyPEM string) error {
	// 获取面板配置
	panelGetConfigReq := &btpanelgosdk.PanelGetConfigRequest{}
	panelGetConfigResp, err := d.sdkClient.PanelGetConfigWithContext(ctx, panelGetConfigReq)
	d.logger.Debug("sdk request 'panel.GetConfig'")
	if err != nil {
		return fmt.Errorf("failed to execute sdk request 'panel.GetConfig': %w", err)
	}

	// 获取网站
	siteData, err := d.findSiteByName(ctx, siteType, siteName)
	if err != nil {
		return err
	}

	// 根据服务器类型部署证书
	pfxRequired := panelUsesIIS(panelGetConfigResp)
	if pfxRequired {
		return d.withPFX(ctx, panelGetConfigResp, certPEM, privkeyPEM, func(path, password string) error {
			reply, err := d.sdkClient.SiteSetSitePFXSSLWithContext(ctx, &btpanelgosdk.SiteSetSitePFXSSLRequest{
				SiteId: lo.ToPtr(siteData.Id), PFX: &path, Password: &password,
			})
			if err != nil {
				return fmt.Errorf("install IIS site certificate: %w", err)
			}
			if !reply.Confirmed() {
				return errors.New("panel did not confirm IIS site binding")
			}
			return nil
		})
	} else {
		// 服务器非 IIS，设置网站 SSL
		siteSetSiteSSLReq := &btpanelgosdk.SiteSetSiteSSLRequest{
			SiteId: lo.ToPtr(siteData.Id),
			Status: lo.ToPtr(true),
			Key:    lo.ToPtr(privkeyPEM),
			Cert:   lo.ToPtr(certPEM),
		}
		_, err := d.sdkClient.SiteSetSiteSSLWithContext(ctx, siteSetSiteSSLReq)
		d.logger.Debug("sdk request 'site.SetSiteSSL'")
		if err != nil {
			return fmt.Errorf("failed to execute sdk request 'site.SetSiteSSL': %w", err)
		}
	}

	return nil
}

func panelUsesIIS(config *btpanelgosdk.PanelGetConfigResponse) bool {
	if config.Site != nil && config.Site.WebServer != "" {
		return strings.EqualFold(config.Site.WebServer, "iis")
	}
	return config.Config != nil && strings.EqualFold(config.Config.WebServer, "iis")
}

func (d *Deployer) deployIISDomains(ctx context.Context, certPEM, keyPEM string) error {
	pair, err := (iisbind.Request{Target: d.config.SiteNames[0], Certificate: certPEM, PrivateKey: keyPEM}).Validate(time.Now())
	if err != nil {
		return err
	}
	names := slices.Clone(d.config.SiteNames)
	seen := make(map[string]bool, len(names))
	for i, name := range names {
		host, _, err := iisbind.Target(name)
		if err != nil || strings.Contains(name, ":") || seen[host] {
			return errors.New("invalid IIS binding domain")
		}
		if pair.Leaf.VerifyHostname(host) != nil {
			return errors.New("certificate does not cover every selected IIS binding")
		}
		seen[host] = true
		names[i] = host
	}
	config, err := d.sdkClient.PanelGetConfigWithContext(ctx, &btpanelgosdk.PanelGetConfigRequest{})
	if err != nil {
		return fmt.Errorf("read IIS configuration: %w", err)
	}
	if !panelUsesIIS(config) {
		return errors.New("selected panel does not report IIS as its web server")
	}
	return d.withPFX(ctx, config, certPEM, keyPEM, func(path, password string) error {
		for i, name := range names {
			if err := d.sdkClient.SetSiteDomainSSL(ctx, name, path, password); err != nil {
				return fmt.Errorf("bind IIS domain %q (%d of %d confirmed): %w", name, i, len(names), err)
			}
		}
		return nil
	})
}

func (d *Deployer) withPFX(ctx context.Context, config *btpanelgosdk.PanelGetConfigResponse, certPEM, keyPEM string, bind func(path, password string) error) (retErr error) {
	if config.Paths == nil {
		return errors.New("panel did not return its software directory")
	}
	dir, ok := windowsPFXDir(config.Paths.Soft)
	if !ok {
		return errors.New("panel returned an invalid software directory")
	}
	if len(certPEM)+len(keyPEM) > iisbind.MaxRequest {
		return errors.New("certificate material exceeds the upload limit")
	}
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return errors.New("invalid certificate or mismatched private key")
	}
	password := rand.Text()
	pfx, err := xcert.TransformCertificateFromPEMToPFX(certPEM, keyPEM, password, nil)
	if err != nil {
		return errors.New("failed to encode certificate and key as PFX")
	}
	defer clear(pfx)
	hash := sha256.Sum256(pfx)
	name := hex.EncodeToString(hash[:]) + ".pfx"
	path := dir + "/" + name
	// An interrupted upload may already have written this operation's file.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := d.sdkClient.RemoveFile(cleanupCtx, path); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("remove temporary IIS certificate: %w", err))
		}
	}()
	reply, err := d.sdkClient.FilesUploadWithContext(ctx, &btpanelgosdk.FilesUploadRequest{
		Path: &dir, Name: &name, Start: lo.ToPtr(int32(0)), Size: lo.ToPtr(int32(len(pfx))), Blob: pfx, Force: lo.ToPtr(false),
	})
	if err != nil {
		return fmt.Errorf("upload IIS certificate: %w", err)
	}
	if !reply.Confirmed() {
		return errors.New("panel did not confirm PFX upload")
	}
	return bind(path, password)
}

func windowsPFXDir(softwareDir string) (string, bool) {
	normalized := strings.ReplaceAll(softwareDir, "\\", "/")
	if len(normalized) < 3 || normalized[1:3] != ":/" || strings.ContainsAny(normalized[3:], "\x00\r\n\t:*?\"<>|") {
		return "", false
	}
	drive := normalized[0] | 0x20
	if drive < 'a' || drive > 'z' {
		return "", false
	}
	subdir := strings.TrimRight(normalized[3:], "/")
	if subdir == "" {
		return normalized[:3] + "temp/ssl/certimate", true
	}
	if subdir != path.Clean(subdir) {
		return "", false
	}
	for part := range strings.SplitSeq(subdir, "/") {
		if part == "" || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return "", false
		}
	}
	return normalized[:3] + subdir + "/temp/ssl/certimate", true
}

func createSDKClient(serverUrl, apiKey string, skipTlsVerify bool) (*btpanelgosdk.Client, error) {
	client, err := btpanelgosdk.NewClient(serverUrl,
		btpanelgosdk.WithApiKey(apiKey),
	)
	if err != nil {
		return nil, err
	}

	if skipTlsVerify {
		client.SetTLSConfig(&tls.Config{InsecureSkipVerify: true})
	}

	return client, nil
}
