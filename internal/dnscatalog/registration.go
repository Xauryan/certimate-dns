package dnscatalog

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Only query registry services published by IANA. User-supplied domain names
// are path components and never determine a network destination.
type registry struct {
	client  *http.Client
	mu      sync.Mutex
	expires time.Time
	servers map[string]string
}

var registrationRegistry = registry{client: &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}}
var unavailable = errors.New("registration dates unavailable")
var noRDAP = errors.New("no secure RDAP service listed")

func (r *registry) get(ctx context.Context, u string, data any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return unavailable
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return unavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return unavailable
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(data)
}
func (r *registry) server(ctx context.Context, tld string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Now().After(r.expires) {
		var bootstrap struct{ Services [][][]string }
		if err := r.get(ctx, "https://data.iana.org/rdap/dns.json", &bootstrap); err != nil {
			return "", err
		}
		servers := map[string]string{}
		for _, entry := range bootstrap.Services {
			if len(entry) != 2 {
				continue
			}
			for _, host := range entry[1] {
				u, err := url.Parse(host)
				if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
					continue
				}
				for _, key := range entry[0] {
					servers[strings.ToLower(key)] = strings.TrimRight(host, "/")
				}
				break
			}
		}
		r.servers = servers
		r.expires = time.Now().Add(24 * time.Hour)
	}
	server := r.servers[tld]
	if server == "" {
		return "", noRDAP
	}
	return server, nil
}

func (r *registry) lookup(ctx context.Context, name string) (created, expires string, err error) {
	ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.ToLower(name), "."))
	if err != nil {
		return "", "", unavailable
	}
	suffix, icann := publicsuffix.PublicSuffix(ascii)
	if !icann || len(ascii) <= len(suffix) {
		return "", "", unavailable
	}
	registered, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil {
		return "", "", unavailable
	}
	server, err := r.server(ctx, registered[strings.LastIndexByte(registered, '.')+1:])
	if errors.Is(err, noRDAP) {
		return r.whois(ctx, registered, (&net.Dialer{Timeout: 10 * time.Second}).DialContext)
	}
	if err != nil {
		return "", "", err
	}
	var doc struct {
		LDHName         string
		ObjectClassName string
		Events          []struct {
			EventAction string
			EventDate   string
		}
	}
	if err := r.get(ctx, server+"/domain/"+url.PathEscape(registered), &doc); err != nil {
		return "", "", err
	}
	if !strings.EqualFold(doc.LDHName, registered) || doc.ObjectClassName != "domain" {
		return "", "", unavailable
	}
	for _, ev := range doc.Events {
		d, err := time.Parse(time.RFC3339, ev.EventDate)
		if err != nil {
			continue
		}
		switch ev.EventAction {
		case "registration":
			created = d.UTC().Format(time.DateOnly)
		case "expiration":
			expires = d.UTC().Format(time.DateOnly)
		}
	}
	if expires == "" {
		return "", "", unavailable
	}
	return created, expires, nil
}

func RefreshRegistration(ctx context.Context, app core.App, id string) (*Domain, error) {
	return refreshRegistration(ctx, app, id, registrationRegistry.lookup)
}
func refreshRegistration(ctx context.Context, app core.App, id string, lookupDates func(context.Context, string) (string, string, error)) (*Domain, error) {
	z, err := Lookup(app, id)
	if err != nil {
		return nil, err
	}
	created, expires, fetchErr := lookupDates(ctx, z.Name)
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	err = app.RunInTransaction(func(tx core.App) error {
		current, err := Lookup(tx, id)
		if err != nil {
			return err
		}
		if current.Name != z.Name || current.ExpiresOn != z.ExpiresOn || current.RegistrationChecked != z.RegistrationChecked || current.AutoRefresh != z.AutoRefresh {
			return domain.NewError(409, "domain changed during registration refresh")
		}
		r, err := tx.FindRecordById("dnsZone", id)
		if err != nil {
			return err
		}
		r.Set("registrationChecked", stamp)
		if fetchErr != nil {
			r.Set("registrationStatus", "failed")
		} else {
			r.Set("registrationStatus", "ok")
			r.Set("registeredOn", created)
			r.Set("expiresOn", expires)
		}
		return tx.SaveWithContext(ctx, r)
	})
	if err != nil {
		return nil, err
	}
	if fetchErr != nil {
		return nil, domain.NewError(502, "registration dates unavailable from registry")
	}
	return Lookup(app, id)
}

func scheduleRegistrationRefresh(app core.App) error {
	return app.Cron().Add("dns-domain-registration-refresh", "3 * * * *", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		var ids []string
		err := app.DB().NewQuery("SELECT z.id" + fromZones + ` AND d.disabled=0 AND z.present=1 AND z.autoRefresh=1 AND
 (z.registrationChecked='' OR julianday(z.registrationChecked) < julianday({:now}) -
 CASE WHEN z.registrationStatus='failed' OR (z.expiresOn<>'' AND date(z.expiresOn)<=date({:now},'+30 days')) THEN 1 ELSE 7 END)
 ORDER BY z.registrationChecked,z.id LIMIT 20`).Bind(dbx.Params{"now": time.Now().UTC().Format(time.RFC3339)}).WithContext(ctx).Column(&ids)
		if err != nil {
			app.Logger().Error("DNS registration refresh query failed")
			return
		}
		for _, id := range ids {
			if ctx.Err() != nil {
				return
			}
			if _, err := RefreshRegistration(ctx, app, id); err != nil {
				app.Logger().Warn("DNS registration refresh failed", "domainId", id)
			}
		}
	})
}
