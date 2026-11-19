package certifiers

import (
	"context"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/stretchr/testify/require"

	"github.com/certimate-go/certimate/internal/domain"
)

// Exercise the registration used by saved workflows, including their legacy aliases.
func TestManagedDNSChallengeFactories(t *testing.T) {
	for _, tc := range []struct {
		providers []domain.ACMEDns01ProviderType
		config    map[string]any
	}{
		{[]domain.ACMEDns01ProviderType{domain.ACMEDns01ProviderTypeAliyun, domain.ACMEDns01ProviderTypeAliyunDNS}, map[string]any{"accessKeyId": "synthetic-id", "accessKeySecret": "synthetic-secret", "resourceGroupId": "synthetic-group"}},
		{[]domain.ACMEDns01ProviderType{domain.ACMEDns01ProviderTypeTencentCloud, domain.ACMEDns01ProviderTypeTencentCloudDNS}, map[string]any{"secretId": "synthetic-id", "secretKey": "synthetic-secret"}},
		{[]domain.ACMEDns01ProviderType{domain.ACMEDns01ProviderTypeCloudflare}, map[string]any{"apiToken": "synthetic-write", "apiTokenForZone": "synthetic-read"}},
	} {
		for _, name := range tc.providers {
			t.Run(string(name), func(t *testing.T) {
				factory, err := ACMEDns01Registries.Get(name)
				require.NoError(t, err)
				_, err = factory(&ProviderFactoryOptions{})
				require.Error(t, err)
				p, err := factory(&ProviderFactoryOptions{ProviderAccessConfig: tc.config, DnsTTL: 600, DnsPropagationTimeout: 321})
				require.NoError(t, err)
				timeout, interval := p.(challenge.ProviderTimeout).Timeout()
				require.Equal(t, 321*time.Second, timeout)
				require.Positive(t, interval)
				// A fresh order has no record to delete, even if another order
				// is solving an authorization for the same identifier.
				require.NoError(t, p.CleanUp(t.Context(), "example.test", "", "synthetic-foreign"))
				require.NoError(t, p.(interface{ RetryCleanup(context.Context) error }).RetryCleanup(t.Context()))
			})
		}
	}
}
