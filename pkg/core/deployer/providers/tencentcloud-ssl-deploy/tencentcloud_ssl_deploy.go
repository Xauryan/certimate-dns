package tencentcloudssldeploy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/samber/lo"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"

	tcssl "github.com/certimate-go/certimate/pkg/sdk3rd-trimmed/github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"

	"github.com/certimate-go/certimate/pkg/core"
	cmgrimpl "github.com/certimate-go/certimate/pkg/core/certmgr/providers/tencentcloud-ssl"
	xwait "github.com/certimate-go/certimate/pkg/utils/wait"
)

type (
	Provider     = core.Deployer
	DeployResult = core.DeployerDeployResult
)

type DeployerConfig struct {
	// 腾讯云 SecretId。
	SecretId string `json:"secretId"`
	// 腾讯云 SecretKey。
	SecretKey string `json:"secretKey"`
	// 腾讯云项目 ID。
	ProjectId int64 `json:"projectId,omitempty"`
	// 腾讯云接口端点。
	Endpoint string `json:"endpoint,omitempty"`
	// 云产品地域。
	ResourceRegion string `json:"resourceRegion,omitempty"`
	// 云产品类型。
	ResourceProduct string `json:"resourceProduct"`
	// 云产品资源 ID 数组。
	ResourceIds []string `json:"resourceIds,omitempty"`
}

type Deployer struct {
	config       *DeployerConfig
	logger       *slog.Logger
	sdkClient    *tcssl.Client
	sdkCertmgr   core.Certmgr
	pollInterval time.Duration
}

var _ Provider = (*Deployer)(nil)

func NewDeployer(config *DeployerConfig) (*Deployer, error) {
	if config == nil {
		return nil, fmt.Errorf("the configuration of the deployer provider is nil")
	}

	client, err := createSDKClient(config.SecretId, config.SecretKey, config.Endpoint, config.ResourceRegion)
	if err != nil {
		return nil, fmt.Errorf("could not create client: %w", err)
	}

	pcertmgr, err := cmgrimpl.NewCertmgr(&cmgrimpl.CertmgrConfig{
		SecretId:  config.SecretId,
		SecretKey: config.SecretKey,
		ProjectId: config.ProjectId,
		Endpoint:  config.Endpoint,
	})
	if err != nil {
		return nil, fmt.Errorf("could not create certmgr: %w", err)
	}

	return &Deployer{
		config:       config,
		logger:       slog.Default(),
		sdkClient:    client,
		sdkCertmgr:   pcertmgr,
		pollInterval: 10 * time.Second,
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
	if d.config.ResourceProduct == "" {
		return nil, fmt.Errorf("config `resourceProduct` is required")
	}
	if len(d.config.ResourceIds) == 0 {
		return nil, fmt.Errorf("config `resourceIds` is required")
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	uploaded, err := d.sdkCertmgr.Upload(ctx, certPEM, privkeyPEM)
	if err != nil {
		return nil, err
	}
	if uploaded == nil || uploaded.CertId == "" {
		return nil, errors.New("Tencent Cloud did not confirm certificate upload")
	}

	submit := tcssl.NewDeployCertificateInstanceRequest()
	submit.CertificateId = common.StringPtr(uploaded.CertId)
	submit.ResourceType = common.StringPtr(d.config.ResourceProduct)
	submit.InstanceIdList = common.StringPtrs(d.config.ResourceIds)
	// The SSL API only uses Status for Cloud Streaming Services.
	if d.config.ResourceProduct == "live" {
		submit.Status = common.Int64Ptr(1)
	}
	result, err := d.sdkClient.DeployCertificateInstanceWithContext(ctx, submit)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("Tencent Cloud did not confirm deployment submission; check remote records before retrying")
	}
	if result == nil || result.Response == nil || result.Response.DeployRecordId == nil || *result.Response.DeployRecordId == 0 {
		return nil, errors.New("Tencent Cloud returned no deployment record")
	}
	recordID := strconv.FormatUint(*result.Response.DeployRecordId, 10)
	if result.Response.DeployStatus != nil && *result.Response.DeployStatus != 1 {
		// DeployStatus=0 returns the ID of a previously submitted job.
		return nil, fmt.Errorf("Tencent Cloud did not create the requested deployment; check existing record %s", recordID)
	}
	d.logger.Info("Tencent Cloud SSL deployment submitted", "recordId", recordID)
	query := tcssl.NewDescribeHostDeployRecordDetailRequest()
	query.DeployRecordId = common.StringPtr(recordID)
	query.Limit = common.Uint64Ptr(200)
	for {
		detail, err := d.sdkClient.DescribeHostDeployRecordDetailWithContext(ctx, query)
		if ctx.Err() != nil {
			return nil, fmt.Errorf("waiting for deployment record %s: %w", recordID, ctx.Err())
		}
		if err != nil || detail == nil || detail.Response == nil || detail.Response.TotalCount == nil {
			return nil, fmt.Errorf("could not read deployment record %s; check remote status before retrying", recordID)
		}
		status := detail.Response
		total, succeeded, failed := *status.TotalCount, lo.FromPtr(status.SuccessTotalCount), lo.FromPtr(status.FailedTotalCount)
		running, pending := lo.FromPtr(status.RunningTotalCount), lo.FromPtr(status.PendingTotalCount)
		if failed > 0 {
			return nil, fmt.Errorf("deployment record %s reports %d failed resources of %d", recordID, failed, total)
		}
		if total > 0 && succeeded == total && running == 0 && pending == 0 {
			return &DeployResult{ExtendedData: map[string]any{"deployRecordId": recordID}}, nil
		}
		d.logger.Debug("waiting for Tencent Cloud SSL deployment", "recordId", recordID, "pending", pending, "running", running, "succeeded", succeeded, "total", total)
		if err := xwait.DelayWithContext(ctx, d.pollInterval); err != nil {
			return nil, fmt.Errorf("waiting for deployment record %s: %w", recordID, err)
		}
	}
}

func createSDKClient(secretId, secretKey, endpoint, region string) (*tcssl.Client, error) {
	credential := common.NewCredential(secretId, secretKey)

	cpf := profile.NewClientProfile()
	if endpoint != "" {
		cpf.HttpProfile.Endpoint = endpoint
	}

	client, err := tcssl.NewClient(credential, region, cpf)
	if err != nil {
		return nil, err
	}

	return client, nil
}
