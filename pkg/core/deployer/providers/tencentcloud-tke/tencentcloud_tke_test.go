package tencentcloudtke

import (
	"context"
	"slices"
	"testing"
)

func TestTKEInstance(t *testing.T) {
	config := DeployerConfig{SecretId: "test-id", SecretKey: "test-key", ProjectId: 2, Region: "ap-guangzhou", ClusterId: "cls-test", Namespace: "apps", SecretName: "api.tls"}
	got, err := deploymentConfig(&config)
	if err != nil || got.ProjectId != 2 || got.ResourceProduct != "tke" || got.ResourceRegion != config.Region || !slices.Equal(got.ResourceIds, []string{"cls-test|apps|api.tls"}) {
		t.Fatal("incorrect TKE deployment configuration")
	}
	for _, tc := range []func(*DeployerConfig){
		func(c *DeployerConfig) { c.Region = "" },
		func(c *DeployerConfig) { c.ClusterId = "cls-one|other" },
		func(c *DeployerConfig) { c.Namespace = "../apps" },
		func(c *DeployerConfig) { c.SecretName = "invalid/TLS" },
		func(c *DeployerConfig) { c.SecretKey = "" },
	} {
		invalid := config
		tc(&invalid)
		if _, err := NewDeployer(&invalid); err == nil {
			t.Fatal("accepted invalid configuration")
		}
	}
}

func TestTKEValidatesKeyBeforeUpload(t *testing.T) {
	d := &deployer{}
	if _, err := d.Deploy(context.Background(), "invalid certificate", "invalid key"); err == nil {
		t.Fatal("accepted an invalid key pair")
	}
}
