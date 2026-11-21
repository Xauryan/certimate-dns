package routes

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"

	"github.com/certimate-go/certimate/internal/certmgmt"
	"github.com/certimate-go/certimate/internal/cfmanagement"
	"github.com/certimate-go/certimate/internal/ddnsfleet"
	"github.com/certimate-go/certimate/internal/dnsadvanced"
	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/certimate-go/certimate/internal/dnsautomation"
	"github.com/certimate-go/certimate/internal/dnsbatch"
	"github.com/certimate-go/certimate/internal/dnscatalog"
	"github.com/certimate-go/certimate/internal/dnscert"
	"github.com/certimate-go/certimate/internal/dnsidentity"
	"github.com/certimate-go/certimate/internal/dnsmanagement"
	"github.com/certimate-go/certimate/internal/dnsmcp"
	"github.com/certimate-go/certimate/internal/dnsoptimize"
	"github.com/certimate-go/certimate/internal/dnsproxysettings"
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/internal/notify"
	"github.com/certimate-go/certimate/internal/repository"
	"github.com/certimate-go/certimate/internal/rest/handlers"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	"github.com/certimate-go/certimate/pkg/utils/http/dnsproxy"
)

type dnsAccess struct {
	app  core.App
	repo *repository.AccessRepository
}

func (d dnsAccess) GetById(ctx context.Context, id string) (*domain.Access, error) {
	enabled, err := dnscatalog.IsEnabled(d.app, id)
	if err != nil {
		return nil, errors.New("DNS account lookup failed")
	}
	if !enabled {
		return nil, domain.ErrRecordNotFound
	}
	return d.repo.GetById(ctx, id)
}
func (d dnsAccess) resolve(ctx context.Context, provider, id string, discovery bool) (dns.Provider, error) {
	a, err := d.GetById(ctx, id)
	if err != nil {
		return nil, err
	}
	if a.Provider != provider {
		return nil, domain.ErrRecordNotFound
	}
	return dnsmanagement.Open(a, discovery, d.app)
}
func (d dnsAccess) scoped(ctx context.Context, provider, id, zone string) (dns.Provider, error) {
	if _, err := dnscatalog.LookupZone(d.app, provider, id, zone); err != nil {
		return nil, err
	}
	return d.resolve(ctx, provider, id, false)
}

// BindDNSConsole starts background jobs only after migrations. Shutdown waits
// for in-flight tasks before PocketBase closes its stores.
func BindDNSConsole(app core.App, r *router.Router[*core.RequestEvent]) (func(), error) {
	d := dnsAccess{app, repository.NewAccessRepository()}
	api := r.Group("/api")
	admin := api.Group("").Bind(apis.RequireSuperuserAuth())
	authenticated := api.Group("").Bind(apis.RequireAuth(core.CollectionNameSuperusers, dnsauth.Members, dnsauth.ZoneSessions))
	handlers.BindDNS(admin, authenticated, d.resolve)
	dnsauth.Bind(api)
	dnscatalog.Bind(admin, d.resolve)
	dnsproxysettings.Bind(api, dnsproxy.NewTransport)
	cfmanagement.Bind(admin, d)
	dnsidentity.Bind(api)
	dnsidentity.BindWebhook(api)
	certs := dnscert.Bind(admin, d.repo, d.resolve)
	dnsmcp.BindCertificateDeployments(admin, certmgmt.DeployPublishedCertificate)
	dnsbatch.Bind(authenticated, d.resolve)
	dnsadvanced.Bind(authenticated, d.resolve)
	if err := dnscatalog.ScheduleReminders(app); err != nil {
		return nil, err
	}
	if err := dnscert.ScheduleNotifications(app); err != nil {
		return nil, err
	}
	auto := dnsautomation.New(app, func(ctx context.Context, t dnsautomation.Target) (dns.Provider, error) {
		a, err := d.GetById(ctx, t.AccountID)
		if err != nil {
			return nil, err
		}
		return d.scoped(ctx, a.Provider, t.AccountID, t.ZoneID)
	}, func(ctx context.Context, e dnsautomation.Event) error {
		var channelErr error
		if e.AccessID != "" {
			channelErr = notify.SendStoredNotification(ctx, app, e.AccessID, "Certimate DNS", fmt.Sprintf("Task %s · Run %s · %s · %s", e.TaskID, e.RunID, e.Action, e.Outcome))
		}
		qqSent, qqErr := dnsidentity.NotifyQQ(ctx, app, e.TaskID, e.RunID, e.Action, e.Outcome)
		if e.AccessID == "" && !qqSent && qqErr == nil {
			return dnsautomation.ErrNoNotification
		}
		return errors.Join(channelErr, qqErr)
	})
	dnsautomation.Bind(admin, auto)
	optimizer := dnsoptimize.New(app, d.scoped)
	optimizer.Bind(admin)
	dnsmcp.Bind(r.RouterGroup, d.resolve, dnsmcp.Services{Cert: certs, Deploy: certmgmt.DeployPublishedCertificate, Automation: auto, Optimize: optimizer})
	ctx, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	fleet := ddnsfleet.New(d.scoped)
	fleet.Bind(api)
	workers.Add(4)
	go func() { defer workers.Done(); fleet.Run(ctx, app) }()
	go func() { defer workers.Done(); auto.Run(ctx) }()
	go func() {
		defer workers.Done()
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if err := certs.RunRenewals(ctx, app); err != nil && ctx.Err() == nil {
					app.Logger().Error("DNS certificate renewal check failed")
				}
			}
		}
	}()
	go func() {
		defer workers.Done()
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if err := dnsmcp.RunCertificateDeployments(ctx, app, certmgmt.DeployPublishedCertificate); err != nil && ctx.Err() == nil {
					app.Logger().Error("DNS certificate deployment check failed")
				}
			}
		}
	}()
	optimizer.Start()
	return sync.OnceFunc(func() { cancel(); optimizer.Stop(); workers.Wait() }), nil
}
