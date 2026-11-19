package main

import (
	"log/slog"
	"os"
	"slices"
	"strings"
	_ "time/tzdata"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/plugins/migratecmd"
	"github.com/pocketbase/pocketbase/tools/hook"

	"github.com/certimate-go/certimate/cmd"
	"github.com/certimate-go/certimate/internal/app"
	"github.com/certimate-go/certimate/internal/dnsidentity"
	"github.com/certimate-go/certimate/internal/rest/routes"
	"github.com/certimate-go/certimate/internal/scheduler"
	"github.com/certimate-go/certimate/internal/settings"
	"github.com/certimate-go/certimate/internal/workflow"
	"github.com/certimate-go/certimate/ui"

	_ "github.com/certimate-go/certimate/migrations"
)

func main() {
	pb := app.GetApp().(*pocketbase.PocketBase)
	if len(os.Args) < 2 {
		slog.Error("[CERTIMATE] missing exec args, maybe you forgot the 'serve' command?")
		os.Exit(1)
		return
	}

	migratecmd.MustRegister(pb, pb.RootCmd, migratecmd.Config{
		Automigrate: strings.HasPrefix(os.Args[0], os.TempDir()),
	})

	pb.RootCmd.AddCommand(cmd.NewInternalCommand(pb))
	pb.RootCmd.AddCommand(cmd.NewVersionCommand(pb))
	pb.RootCmd.AddCommand(cmd.NewWinscCommand(pb))
	pb.RootCmd.AddCommand(dnsidentity.NewResetCommand(pb))
	pb.RootCmd.AddCommand(dnsidentity.NewAdminResetCommand(pb))

	isServeCmd := slices.Contains(os.Args[1:], "serve")

	if isServeCmd {
		var stopDNS func()
		dnsidentity.Install(pb)
		pb.OnBootstrap().BindFunc(func(e *core.BootstrapEvent) error {
			if err := e.Next(); err != nil {
				return err
			}

			settings.Setup()

			return nil
		})

		pb.OnServe().Bind(&hook.Handler[*core.ServeEvent]{
			Func: func(e *core.ServeEvent) error {
				e.Router.
					GET("/{path...}", apis.Static(ui.DistDirFS, false)).
					Bind(apis.Gzip())
				return e.Next()
			},
			Priority: 999,
		})

		pb.OnServe().BindFunc(func(e *core.ServeEvent) error {
			scheduler.Setup()
			workflow.Setup()
			routes.BindRouter(e.Router)
			stop, err := routes.BindDNSConsole(e.App, e.Router)
			if err != nil {
				return err
			}
			stopDNS = stop

			if err := e.Next(); err != nil {
				stop()
				return err
			}

			slog.Info("[CERTIMATE] Serving on " + e.Server.Addr)
			return nil
		})

		pb.OnTerminate().BindFunc(func(e *core.TerminateEvent) error {
			if stopDNS != nil {
				stopDNS()
			}
			if pb.IsBootstrapped() {
				workflow.Teardown()
			}

			return e.Next()
		})
	}

	if err := cmd.Serve(pb); err != nil {
		if isServeCmd {
			slog.Error("[CERTIMATE] Serve failed.", slog.Any("error", err))
		} else {
			slog.Error("[CERTIMATE] Start failed.", slog.Any("error", err))
		}
	}
}
