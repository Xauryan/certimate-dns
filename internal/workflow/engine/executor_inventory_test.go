package engine

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/certimate-go/certimate/internal/domain"
)

type inventoryTestRepository struct {
	certificateRepository // Only a lookup by ID is valid when selecting an existing certificate.
	cert                  *domain.Certificate
	err                   error
}

func (r inventoryTestRepository) GetById(_ context.Context, id string) (*domain.Certificate, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.cert == nil || r.cert.Id != id {
		return nil, domain.ErrRecordNotFound
	}
	return r.cert, nil
}

func TestInventoryInputResolvesLiveCertificate(t *testing.T) {
	now := time.Now()
	cert := inventoryTestCertificate(t, "inventoryrecord", now.Add(-time.Minute), now.Add(time.Hour))
	var logs bytes.Buffer
	node := &Node{Id: "input", Type: NodeTypeBizUpload, Data: domain.WorkflowNodeData{Config: domain.WorkflowNodeConfig{"source": "inventory", "certificateId": cert.Id}}}
	execCtx := (&NodeExecutionContext{}).SetExecutingNode(node).SetContext(context.Background())
	executor := bizUploadNodeExecutor{nodeExecutor: nodeExecutor{logger: slog.New(slog.NewTextHandler(&logs, nil))}, certificateRepo: inventoryTestRepository{cert: cert}}
	result, err := executor.Execute(execCtx)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outputs) != 1 || result.Outputs[0].Value != "certificate#"+cert.Id || !result.Outputs[0].Persistent {
		t.Fatal("inventory input did not emit the existing certificate reference")
	}
	if strings.Contains(logs.String(), "PRIVATE KEY") {
		t.Fatal("private key in log")
	}
	cert.IsRevoked = true
	if result, err = executor.Execute(execCtx); err == nil || len(result.Outputs) != 0 {
		t.Fatal("revoked inventory certificate was reused")
	}
	cert.IsRevoked = false
	cert.DeletedAt = &now
	if _, err = executor.Execute(execCtx); err == nil {
		t.Fatal("deleted certificate was accepted")
	}
	cert.DeletedAt = nil
	cert.PrivateKey = "invalid synthetic private key"
	if _, err = executor.Execute(execCtx); err == nil {
		t.Fatal("certificate with unusable private key was accepted")
	}
	node.Data.Config["source"] = "form"
	node.Data.Config["privateKey"] = "synthetic-sensitive-marker"
	executor.wfoutputRepo = emptyInventoryOutput{}
	_, _ = executor.Execute(execCtx)
	if strings.Contains(logs.String(), "synthetic-sensitive-marker") {
		t.Fatal("input form private key in logs")
	}
	node.Data.Config["source"] = "synthetic-sensitive-marker"
	if _, err := executor.Execute(execCtx); err == nil || strings.Contains(err.Error(), "synthetic-sensitive-marker") {
		t.Fatal("unknown source was accepted or disclosed")
	}
	node.Data.Config["source"] = "inventory"
	executor.certificateRepo = inventoryTestRepository{err: errors.New("synthetic-sensitive-marker")}
	if _, err := executor.Execute(execCtx); err == nil || strings.Contains(err.Error(), "synthetic-sensitive-marker") || strings.Contains(logs.String(), "synthetic-sensitive-marker") {
		t.Fatal("inventory lookup diagnostics disclosed untrusted content")
	}
}

type emptyInventoryOutput struct{ workflowOutputRepository }

func (emptyInventoryOutput) GetByWorkflowIdAndNodeId(context.Context, string, string) (*domain.WorkflowOutput, error) {
	return nil, domain.ErrRecordNotFound
}

func TestDeploySkipUsesInventoryCertificateReference(t *testing.T) {
	cfg := domain.WorkflowNodeConfig{"provider": "local", "skipOnLastSucceeded": true, "certificateOutputNodeId": "input"}
	ctx := (&NodeExecutionContext{}).SetExecutingNode(&Node{Data: domain.WorkflowNodeData{Config: cfg}})
	last := &domain.WorkflowOutput{Succeeded: true, NodeConfig: cfg}
	ne := bizDeployNodeExecutor{}
	if skip, _ := ne.checkCanSkip(ctx, last, "first", true); skip {
		t.Fatal("legacy output proves no inventory identity")
	}
	if skip, _ := ne.checkCanSkip(ctx, last, "first", false); !skip {
		t.Fatal("existing upload skip regressed")
	}
	last.Outputs = []*domain.WorkflowOutputEntry{{Name: "deployedCertificate", Value: "certificate#first"}}
	if skip, _ := ne.checkCanSkip(ctx, last, "first", true); !skip {
		t.Fatal("same destination and selection should skip")
	}
	if skip, _ := ne.checkCanSkip(ctx, last, "second", true); skip {
		t.Fatal("rebound inventory certificate skipped")
	}
}
