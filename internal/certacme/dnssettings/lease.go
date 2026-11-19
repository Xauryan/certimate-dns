// Package dnssettings coordinates process-wide settings in lego v5.3.1.
// Identically configured DNS orders can run together. A different resolver
// or CNAME policy must wait until all current orders finish cleanup.
package dnssettings

import (
	"context"
	"os"
	"slices"
	"strconv"
	"sync"

	"github.com/go-acme/lego/v5/challenge/dns01"
)

const cnameEnv = "LEGO_DISABLE_CNAME_SUPPORT"

var (
	mu     sync.Mutex
	active *session
)

type session struct {
	nameservers        []string
	disableFollowCNAME bool
	users              int
	done               chan struct{}

	originalClient *dns01.Client
	originalCNAME  string
	hadCNAME       bool
}

func Acquire(ctx context.Context, nameservers []string, disableFollowCNAME bool) (func(), error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		mu.Lock()
		if active == nil {
			cname, hadCNAME := os.LookupEnv(cnameEnv)
			if err := os.Setenv(cnameEnv, strconv.FormatBool(disableFollowCNAME)); err != nil {
				mu.Unlock()
				return nil, err
			}
			active = &session{
				nameservers:        slices.Clone(nameservers),
				disableFollowCNAME: disableFollowCNAME,
				done:               make(chan struct{}),
				originalClient:     dns01.DefaultClient(),
				originalCNAME:      cname,
				hadCNAME:           hadCNAME,
			}
			dns01.SetDefaultClient(dns01.NewClient(&dns01.Options{RecursiveNameservers: slices.Clone(nameservers)}))
		}
		if active.disableFollowCNAME == disableFollowCNAME && slices.Equal(active.nameservers, nameservers) {
			active.users++
			release := sync.OnceFunc(active.release)
			mu.Unlock()
			return release, nil
		}
		done := active.done
		mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-done:
		}
	}
}

func (s *session) release() {
	mu.Lock()
	defer mu.Unlock()
	s.users--
	if s.users != 0 {
		return
	}
	dns01.SetDefaultClient(s.originalClient)
	if s.hadCNAME {
		_ = os.Setenv(cnameEnv, s.originalCNAME)
	} else {
		_ = os.Unsetenv(cnameEnv)
	}
	active = nil
	close(s.done)
}
