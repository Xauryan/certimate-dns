// Package managedtxt solves DNS-01 using providers that add and delete individual
// records. Concurrent orders (including separate worker processes) never replace
// a TXT RRset. Each order owns only the record IDs returned by its create calls.
package managedtxt

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/challenge/dns01"
	"golang.org/x/net/idna"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type Writer interface {
	CreateDNSRecord(context.Context, string, dns.RecordInput) (string, error)
	DeleteDNSRecord(context.Context, string, string) (string, error)
}

type Config struct {
	TTL                int
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
	RequestTimeout     time.Duration
	// ZoneIDByName is needed when the provider uses opaque IDs for zones.
	ZoneIDByName func(context.Context, string) (string, error)
	QuoteTXT     bool
}

type Provider struct {
	writer Writer
	config Config

	mu      sync.Mutex
	created map[challengeKey]record
}

type challengeKey struct {
	domain    string
	valueHash [sha256.Size]byte
}

type record struct {
	zoneID   string
	recordID string
}

func New(writer Writer, config Config) *Provider {
	return &Provider{writer: writer, config: config, created: make(map[challengeKey]record)}
}

func (p *Provider) Timeout() (time.Duration, time.Duration) {
	return p.config.PropagationTimeout, p.config.PollingInterval
}

func keyFor(domain, keyAuth string) (challengeKey, error) {
	// ACME returns the bare identifier for wildcard authorizations. Accept
	// either spelling from direct challenger callers.
	name, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.TrimPrefix(domain, "*."), "."))
	if err != nil || name == "" {
		return challengeKey{}, errors.New("invalid DNS challenge domain")
	}
	return challengeKey{domain: strings.ToLower(name), valueHash: sha256.Sum256([]byte(keyAuth))}, nil
}

func (p *Provider) Present(ctx context.Context, domain, token, keyAuth string) error {
	key, err := keyFor(domain, keyAuth)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.created[key]; exists {
		return nil
	}

	info := dns01.GetChallengeInfo(ctx, key.domain, keyAuth)
	zone, err := dns01.DefaultClient().FindZoneByFqdn(ctx, info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("resolve DNS challenge zone: %w", err)
	}
	zoneID := strings.ToLower(dns01.UnFqdn(zone))
	if p.config.ZoneIDByName != nil {
		zoneID, err = p.config.ZoneIDByName(ctx, zoneID)
		if err != nil {
			return err
		}
	}
	content := info.Value
	if p.config.QuoteTXT {
		content = `"` + content + `"`
	}
	// A zero HTTP timeout in lego lets the order context bound the request.
	if p.config.RequestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.config.RequestTimeout)
		defer cancel()
	}
	recordID, err := p.writer.CreateDNSRecord(ctx, zoneID, dns.RecordInput{
		Type:    "TXT",
		Name:    strings.ToLower(dns01.UnFqdn(info.EffectiveFQDN)),
		Content: content,
		TTL:     p.config.TTL,
	})
	if err != nil {
		return err
	}
	if recordID == "" {
		return errors.New("provider returned no DNS challenge record ID")
	}
	p.created[key] = record{zoneID: zoneID, recordID: recordID}
	return nil
}

func (p *Provider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	key, err := keyFor(domain, keyAuth)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	owned, exists := p.created[key]
	if !exists {
		// lego also calls CleanUp after a failed Present.
		return nil
	}
	cleanupCtx, cancel := p.cleanupContext(ctx)
	defer cancel()
	return p.remove(cleanupCtx, key, owned)
}

// RetryCleanup gets one final opportunity to remove acknowledged creations.
// lego reports failed cleanup in its log and may still return an issued certificate.
func (p *Provider) RetryCleanup(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	cleanupCtx, cancel := p.cleanupContext(ctx)
	defer cancel()
	var errs []error
	for key, owned := range p.created {
		if err := p.remove(cleanupCtx, key, owned); err != nil {
			errs = append(errs, fmt.Errorf("challenge for %s (zone %s, record %s): %w", key.domain, owned.zoneID, owned.recordID, err))
		}
	}
	return errors.Join(errs...)
}

func (p *Provider) cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := p.config.RequestTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return context.WithTimeout(context.WithoutCancel(ctx), timeout)
}

func (p *Provider) remove(ctx context.Context, key challengeKey, owned record) error {
	// Use the zone ID captured at Present, even if the CNAME changed.
	deleted, err := p.writer.DeleteDNSRecord(ctx, owned.zoneID, owned.recordID)
	if err != nil {
		return err
	}
	if deleted != owned.recordID {
		return errors.New("provider did not confirm deletion of the challenge record")
	}
	delete(p.created, key)
	return nil
}
