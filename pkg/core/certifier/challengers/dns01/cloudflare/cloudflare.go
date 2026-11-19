package cloudflare

import (
	"fmt"
	"time"

	"github.com/go-acme/lego/v5/providers/dns/cloudflare"

	"github.com/certimate-go/certimate/pkg/core"
	"github.com/certimate-go/certimate/pkg/core/certifier/challengers/dns01/internal/managedtxt"
	cf "github.com/certimate-go/certimate/pkg/sdk3rd/cloudflare"
)

type ChallengerConfig struct {
	ApiToken              string `json:"apiToken"`
	ApiTokenForZone       string `json:"apiTokenForZone,omitempty"`
	DnsPropagationTimeout int    `json:"dnsPropagationTimeout,omitempty"`
	DnsTTL                int    `json:"dnsTTL,omitempty"`
}

func NewChallenger(config *ChallengerConfig) (core.ACMEChallenger, error) {
	if config == nil {
		return nil, fmt.Errorf("the configuration of the acme challenge provider is nil")
	}

	providerConfig := cloudflare.NewDefaultConfig()
	if config.DnsPropagationTimeout != 0 {
		providerConfig.PropagationTimeout = time.Duration(config.DnsPropagationTimeout) * time.Second
	}
	if config.DnsTTL != 0 {
		providerConfig.TTL = config.DnsTTL
	}

	if providerConfig.TTL < 120 {
		return nil, fmt.Errorf("cloudflare: DNS challenge TTL must be at least 120 seconds")
	}
	records, err := cf.NewClient(cf.WithApiToken(config.ApiToken))
	if err != nil {
		return nil, err
	}
	records.SetTimeout(providerConfig.HTTPClient.Timeout)
	zones := records
	if config.ApiTokenForZone != "" && config.ApiTokenForZone != config.ApiToken {
		zones, err = cf.NewClient(cf.WithApiToken(config.ApiTokenForZone))
		if err != nil {
			return nil, err
		}
		zones.SetTimeout(providerConfig.HTTPClient.Timeout)
	}
	return managedtxt.New(records, managedtxt.Config{
		RequestTimeout:     providerConfig.HTTPClient.Timeout,
		ZoneIDByName:       zones.ZoneIDByName,
		QuoteTXT:           true,
		TTL:                providerConfig.TTL,
		PropagationTimeout: providerConfig.PropagationTimeout,
		PollingInterval:    providerConfig.PollingInterval,
	}), nil
}
