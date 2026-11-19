package dnssettings

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/stretchr/testify/require"
)

func TestResolverSettingsSharedOnlyWithMatchingOrders(t *testing.T) {
	t.Setenv(cnameEnv, "true")
	before := dns01.DefaultClient()
	first, err := Acquire(t.Context(), []string{"127.0.0.1:53001"}, false)
	require.NoError(t, err)
	client := dns01.DefaultClient()
	second, err := Acquire(t.Context(), []string{"127.0.0.1:53001"}, false)
	require.NoError(t, err)
	require.Same(t, client, dns01.DefaultClient())
	first()
	first()
	require.Equal(t, "false", os.Getenv(cnameEnv))

	for _, conflict := range []struct {
		servers []string
		cname   bool
	}{
		{[]string{"127.0.0.1:53002"}, false},
		{[]string{"127.0.0.1:53001"}, true},
	} {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		_, err = Acquire(ctx, conflict.servers, conflict.cname)
		cancel()
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Same(t, client, dns01.DefaultClient())
	}
	second()
	require.Same(t, before, dns01.DefaultClient())
	require.Equal(t, "true", os.Getenv(cnameEnv))

	release, err := Acquire(t.Context(), []string{"127.0.0.1:53002"}, true)
	require.NoError(t, err)
	require.NotSame(t, client, dns01.DefaultClient())
	require.Equal(t, "true", os.Getenv(cnameEnv))
	release()
}
