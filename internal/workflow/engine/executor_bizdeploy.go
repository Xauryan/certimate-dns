package engine

import (
	"fmt"
	"log/slog"
	"maps"
	"reflect"
	"strings"
	"time"

	"github.com/certimate-go/certimate/internal/certmgmt"
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/internal/repository"
)

/**
 * Inputs:
 *   - ref: "certificate": string
 *
 * Variables:
 *   - "node.skipped": boolean
 */
type bizDeployNodeExecutor struct {
	nodeExecutor

	accessRepo      accessRepository
	certificateRepo certificateRepository
	wfoutputRepo    workflowOutputRepository
}

func (ne *bizDeployNodeExecutor) Execute(execCtx *NodeExecutionContext) (*NodeExecutionResult, error) {
	execRes := newNodeExecutionResult(execCtx.Node)

	nodeCfg := execCtx.Node.Data.Config.AsBizDeploy()
	ne.logger.Info("ready to deploy certificate ...", slog.String("provider", nodeCfg.Provider), slog.String("accessId", nodeCfg.ProviderAccessId))

	// 查询上次执行结果
	lastOutput, err := ne.getLastOutputArtifacts(execCtx)
	if err != nil {
		return execRes, err
	} else {
		if lastOutput != nil {
			ne.logger.Info(fmt.Sprintf("found last node output #%s record", lastOutput.RunId))
		}
	}

	// 获取前序节点输出证书
	var inputCertificate *domain.Certificate
	if inputState, ok := execCtx.inputs.Get(nodeCfg.CertificateOutputNodeId, "certificate"); ok {
		if inputStateValue, ok := inputState.Value.(string); ok {
			s := strings.Split(inputStateValue, "#")
			if len(s) == 2 {
				certificate, err := ne.certificateRepo.GetById(execCtx.Context(), s[1])
				if err != nil {
					ne.logger.Warn("could not get input certificate")
					return execRes, err
				}

				inputCertificate = certificate
			}
		}
	}
	if inputCertificate == nil {
		return execRes, fmt.Errorf("invalid input certificate")
	}

	if inputCertificate.IsRevoked {
		return execRes, fmt.Errorf("input certificate has been revoked")
	}
	inputNode, found := execCtx.RunGraph.GetNodeById(nodeCfg.CertificateOutputNodeId)
	fromInventory := found && inputNode.Type == NodeTypeBizUpload && inputNode.Data.Config.AsBizUpload().Source == BizUploadSourceInventory
	inputTime := inputCertificate.CreatedAt
	if fromInventory {
		inputTime = inputCertificate.UpdatedAt
		if err := validateInventoryCertificate(inputCertificate, time.Now()); err != nil {
			return execRes, err
		}
	}

	// 读取部署提供商授权
	providerAccessConfig := make(map[string]any)
	if nodeCfg.ProviderAccessId != "" {
		if access, err := ne.accessRepo.GetById(execCtx.Context(), nodeCfg.ProviderAccessId); err != nil {
			return nil, fmt.Errorf("failed to get access #%s record: %w", nodeCfg.ProviderAccessId, err)
		} else {
			expected, _, _ := strings.Cut(nodeCfg.Provider, "-")
			if access.Provider != expected {
				return execRes, fmt.Errorf("deployment provider %q requires a %s credential", nodeCfg.Provider, expected)
			}
			providerAccessConfig = access.Config
		}
	}

	extendedConfig := nodeCfg.ProviderConfig
	qzyunBinding, documentID := "", ""
	if nodeCfg.Provider == "qzyun" {
		qzyunBinding = qzyunBindingHash(nodeCfg, providerAccessConfig)
		documentID = previousQzyunDocumentID(lastOutput, qzyunBinding)
		if documentID != "" {
			extendedConfig = maps.Clone(extendedConfig)
			extendedConfig["target"] = documentID
		}
	}

	// 检测是否可以跳过本次执行
	if lastOutput != nil && inputTime.Before(lastOutput.UpdatedAt) && (nodeCfg.Provider != "qzyun" || documentID != "") {
		if skippable, reason := ne.checkCanSkip(execCtx, lastOutput, inputCertificate.Id, fromInventory); skippable {
			ne.logger.Info(fmt.Sprintf("skip this deployment, because %s", reason))

			execRes.AddVariableWithScope(execCtx.Node.Id, stateVarKeyNodeSkipped, true, stateValTypeBoolean)
			return execRes, nil
		} else if reason != "" {
			ne.logger.Info(fmt.Sprintf("re-deploy, because %s", reason))

			execRes.AddVariableWithScope(execCtx.Node.Id, stateVarKeyNodeSkipped, false, stateValTypeBoolean)
		}
	} else {
		execRes.AddVariableWithScope(execCtx.Node.Id, stateVarKeyNodeSkipped, false, stateValTypeBoolean)
	}

	// 部署证书
	deployer := certmgmt.NewClient(certmgmt.WithLogger(ne.logger))
	deployReq := &certmgmt.DeployCertificateRequest{
		Provider:               domain.DeploymentProviderType(nodeCfg.Provider),
		ProviderAccessConfig:   providerAccessConfig,
		ProviderExtendedConfig: extendedConfig,
		CertificatePEM:         inputCertificate.Certificate,
		PrivateKeyPEM:          inputCertificate.PrivateKey,
	}
	result, err := deployer.DeployCertificate(execCtx.Context(), deployReq)
	if err != nil {
		ne.logger.Warn("could not deploy certificate")
		return execRes, err
	}

	// Only keep the document ID returned after Qzyun confirms the update and binding.
	if qzyunBinding != "" {
		if id, ok := result.ExtendedData["documentId"].(string); ok && qzyunDocumentIDPattern.MatchString(id) {
			execRes.AddOutputWithPersistent(stateIOTypeRef, "qzyunDocument", qzyunBinding+"#"+id, stateValTypeString)
		}
	}

	// 节点输出
	execRes.AddOutputWithPersistent(stateIOTypeRef, "deployedCertificate", domain.CollectionNameCertificate+"#"+inputCertificate.Id, stateValTypeString)

	ne.logger.Info("deployment completed")
	return execRes, nil
}

func (ne *bizDeployNodeExecutor) getLastOutputArtifacts(execCtx *NodeExecutionContext) (*domain.WorkflowOutput, error) {
	lastOutput, err := ne.wfoutputRepo.GetByWorkflowIdAndNodeId(execCtx.Context(), execCtx.WorkflowId, execCtx.Node.Id)
	if err != nil && !domain.IsRecordNotFoundError(err) {
		return nil, fmt.Errorf("failed to get last output record of node #%s: %w", execCtx.Node.Id, err)
	}

	return lastOutput, nil
}

func (ne *bizDeployNodeExecutor) checkCanSkip(execCtx *NodeExecutionContext, lastOutput *domain.WorkflowOutput, certificateID string, fromInventory bool) (_skip bool, _reason string) {
	thisNodeCfg := execCtx.Node.Data.Config.AsBizDeploy()

	if lastOutput != nil && lastOutput.Succeeded {
		// 比较和上次部署时的关键配置（即影响证书部署的）参数是否一致
		lastNodeCfg := lastOutput.NodeConfig.AsBizDeploy()

		sameCertificate := false
		for _, output := range lastOutput.Outputs {
			if output != nil && output.Name == "deployedCertificate" {
				if output.Value != domain.CollectionNameCertificate+"#"+certificateID {
					return false, "the selected certificate changed"
				}
				sameCertificate = true
				break
			}
		}
		// Deployments predating inventory inputs have no certificate ID receipt.
		if fromInventory && !sameCertificate {
			return false, "the previous deployment has no inventory certificate reference"
		}
		if thisNodeCfg.CertificateOutputNodeId != lastNodeCfg.CertificateOutputNodeId || thisNodeCfg.Provider != lastNodeCfg.Provider {
			return false, "the certificate input node or deployment provider changed"
		}
		if thisNodeCfg.ProviderAccessId != lastNodeCfg.ProviderAccessId {
			return false, "the configuration item 'ProviderAccessId' changed"
		}
		if !reflect.DeepEqual(thisNodeCfg.ProviderConfig, lastNodeCfg.ProviderConfig) {
			return false, "the configuration item 'ProviderConfig' changed"
		}

		if thisNodeCfg.SkipOnLastSucceeded {
			return true, "the last deployment already completed"
		}
	}

	return false, ""
}

func newBizDeployNodeExecutor() NodeExecutor {
	return &bizDeployNodeExecutor{
		nodeExecutor:    nodeExecutor{logger: slog.Default()},
		accessRepo:      repository.NewAccessRepository(),
		certificateRepo: repository.NewCertificateRepository(),
		wfoutputRepo:    repository.NewWorkflowOutputRepository(),
	}
}
