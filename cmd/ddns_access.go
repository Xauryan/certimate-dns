package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/pocketbase/pocketbase/core"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/certimate-go/certimate/internal/dnscatalog"
	"github.com/certimate-go/certimate/internal/dnsmanagement"
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/internal/repository"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func registerDDNSAccessCommands(root *cobra.Command, app core.App) {
	access := &cobra.Command{Use: "access", Short: "Provision a DNS credential with the server stopped"}
	access.AddCommand(newDDNSCloudflareImportCommand(app, func(credential *domain.Access) (dns.Provider, error) {
		return dnsmanagement.Open(credential, false, app)
	}))
	root.AddCommand(access)
}

func newDDNSCloudflareImportCommand(app core.App, open func(*domain.Access) (dns.Provider, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "import-cloudflare NAME ZONE_ID ZONE_NAME",
		Short: "Read a Cloudflare API token from standard input and import one existing zone",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			zoneName := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(args[2]), "."))
			if name == "" || utf8.RuneCountInString(name) > 128 || strings.IndexFunc(name, unicode.IsControl) >= 0 || zoneName == "" {
				return errors.New("invalid credential or zone name")
			}
			token, err := readDDNSAccessToken(cmd)
			if err != nil {
				return err
			}
			defer clear(token)
			credential := &domain.Access{
				Name: name, Provider: "cloudflare",
				Config: map[string]any{"authMethod": "apitoken", "apiToken": string(token)},
			}
			provider, err := open(credential)
			if err != nil {
				return errors.New("could not initialize the Cloudflare DNS provider")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
			defer cancel()
			zoneID := args[1]
			page, err := provider.DNSRecords(ctx, zoneID, 1, "")
			if err != nil || page == nil || page.Info.Page != 1 || page.Info.Total < len(page.Items) {
				return errors.New("Cloudflare credential could not read the selected zone records")
			}

			var zone *dnscatalog.Domain
			err = app.RunInTransaction(func(tx core.App) error {
				created, err := repository.NewAccessRepositoryFor(tx).CreateDNSCredential(ctx, credential)
				if err != nil {
					return err
				}
				_, err = dnscatalog.ImportZones(ctx, tx, created.Id, []string{zoneID},
					func(_ context.Context, _, _ string, _ bool) (dns.Provider, error) { return provider, nil })
				if err != nil {
					return errDDNSZoneImport
				}
				zone, err = dnscatalog.LookupZone(tx, "cloudflare", created.Id, zoneID)
				if err != nil || zone.Name != zoneName {
					return errDDNSZoneMismatch
				}
				return nil
			})
			if err != nil {
				var known *domain.Error
				if errors.As(err, &known) && known.Code == 409 {
					return known
				}
				return fmt.Errorf("could not provision the Cloudflare DNS credential: %w", sanitizeDDNSAccessError(err))
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(ddnsZoneSummary(zone))
		},
	}
}

var (
	errDDNSZoneImport   = errors.New("Cloudflare credential could not import the selected zone")
	errDDNSZoneMismatch = errors.New("Cloudflare zone identity did not match the expected zone name")
)

func sanitizeDDNSAccessError(err error) error {
	switch {
	case errors.Is(err, errDDNSZoneImport), errors.Is(err, errDDNSZoneMismatch):
		return err
	default:
		return errors.New("could not save the credential or zone")
	}
}

func readDDNSAccessToken(cmd *cobra.Command) ([]byte, error) {
	const maxTokenBytes = 16384
	input := cmd.InOrStdin()
	var token []byte
	var err error
	if f, ok := input.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprint(cmd.ErrOrStderr(), "Cloudflare API token: ")
		token, err = term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(cmd.ErrOrStderr())
	} else {
		token, err = io.ReadAll(io.LimitReader(input, maxTokenBytes+3))
		token = bytes.TrimSuffix(bytes.TrimSuffix(token, []byte("\n")), []byte("\r"))
	}
	if err != nil {
		clear(token)
		return nil, errors.New("could not read the Cloudflare API token")
	}
	if len(token) == 0 || len(token) > maxTokenBytes ||
		bytes.IndexFunc(token, func(r rune) bool { return r < '!' || r > '~' }) >= 0 {
		clear(token)
		return nil, errors.New("provide one non-empty Cloudflare API token on standard input")
	}
	return token, nil
}
