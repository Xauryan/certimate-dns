package certacme

import (
	"context"
	"fmt"

	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/internal/settings"
	xmaps "github.com/certimate-go/certimate/pkg/utils/maps"
)

type ACMEConfigOptions struct {
	CAProvider               domain.CAProviderType
	CAProviderAccessConfig   map[string]any
	CAProviderExtendedConfig map[string]any
	CertifierKeyAlgorithm    domain.CertificateKeyAlgorithmType
}

type ACMEConfig struct {
	CAProvider domain.CAProviderType
	CADirUrl   string
	EABKid     string
	EABHmacKey string
	googleEAB  *googleEABProvider
}

func CreateACMEConfig(ctx context.Context, options *ACMEConfigOptions) (*ACMEConfig, error) {
	if options == nil {
		return nil, fmt.Errorf("the options is nil")
	}

	provider := options.CAProvider
	providerAccessCfg := options.CAProviderAccessConfig

	if provider.String() == "" {
		globalSettingsForSSLProvider := settings.GetGlobalSettingsForSSLProvider()
		provider = globalSettingsForSSLProvider.Provider
		providerAccessCfg = globalSettingsForSSLProvider.Configs[globalSettingsForSSLProvider.Provider]
	}

	if provider.String() == "" {
		// default CA: Let's Encrypt
		provider = domain.CAProviderTypeLetsEncrypt
	}

	acmeDirUrl, err := getCADirUrl(provider, providerAccessCfg, options.CertifierKeyAlgorithm)
	if err != nil {
		return nil, err
	}

	acmeEab := domain.AccessConfigForACMEExternalAccountBinding{}
	if err := xmaps.Populate(providerAccessCfg, &acmeEab); err != nil {
		if provider == domain.CAProviderTypeGoogleTrustServices {
			return nil, fmt.Errorf("invalid Google Public CA configuration")
		}
		return nil, err
	}

	config := &ACMEConfig{
		CAProvider: provider,
		CADirUrl:   acmeDirUrl,
		EABKid:     acmeEab.EabKid,
		EABHmacKey: acmeEab.EabHmacKey,
	}
	if provider == domain.CAProviderTypeGoogleTrustServices {
		var credentials domain.AccessConfigForGoogleTrustServices
		if err := xmaps.Populate(providerAccessCfg, &credentials); err != nil {
			return nil, fmt.Errorf("invalid Google Public CA configuration")
		}
		switch credentials.EABMode {
		case "", "manual":
		case "auto":
			if config.EABKid != "" || config.EABHmacKey != "" {
				return nil, fmt.Errorf("automatic Google Public CA registration requires an empty manual EAB pair")
			}
			config.googleEAB, err = newGoogleEABProvider(credentials, acmeDirUrl)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("invalid Google Public CA EAB mode")
		}
	}
	return config, nil
}
