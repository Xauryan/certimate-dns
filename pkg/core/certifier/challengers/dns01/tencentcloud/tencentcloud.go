package tencentcloud

import (
	"fmt"
	"time"

	"github.com/go-acme/lego/v5/providers/dns/tencentcloud"

	"github.com/certimate-go/certimate/internal/dnsmanagement"
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/pkg/core"
	"github.com/certimate-go/certimate/pkg/core/certifier/challengers/dns01/internal/managedtxt"
)

type ChallengerConfig struct {
	SecretId              string `json:"secretId"`
	SecretKey             string `json:"secretKey"`
	DnsPropagationTimeout int    `json:"dnsPropagationTimeout,omitempty"`
	DnsTTL                int    `json:"dnsTTL,omitempty"`
}

func NewChallenger(config *ChallengerConfig) (core.ACMEChallenger, error) {
	if config == nil {
		return nil, fmt.Errorf("the configuration of the acme challenge provider is nil")
	}

	providerConfig := tencentcloud.NewDefaultConfig()
	if config.DnsPropagationTimeout != 0 {
		providerConfig.PropagationTimeout = time.Duration(config.DnsPropagationTimeout) * time.Second
	}
	if config.DnsTTL != 0 {
		providerConfig.TTL = config.DnsTTL
	}

	provider, err := dnsmanagement.NewTencent(&domain.Access{Config: map[string]any{
		"secretId":  config.SecretId,
		"secretKey": config.SecretKey,
	}})
	if err != nil {
		return nil, err
	}
	return managedtxt.New(provider, managedtxt.Config{
		RequestTimeout:     providerConfig.HTTPTimeout,
		TTL:                providerConfig.TTL,
		PropagationTimeout: providerConfig.PropagationTimeout,
		PollingInterval:    providerConfig.PollingInterval,
	}), nil
}
