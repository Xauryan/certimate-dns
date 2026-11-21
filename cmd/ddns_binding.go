package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/spf13/cobra"

	"github.com/certimate-go/certimate/internal/ddnsfleet"
	"github.com/certimate-go/certimate/internal/dnscatalog"
	"github.com/certimate-go/certimate/internal/dnsmanagement"
	"github.com/certimate-go/certimate/internal/repository"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type ddnsCatalogZone struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Provider  string `json:"provider"`
	AccessID  string `json:"accessId"`
	ZoneID    string `json:"zoneId"`
	Available bool   `json:"available"`
}

func ddnsZoneSummary(zone *dnscatalog.Domain) ddnsCatalogZone {
	return ddnsCatalogZone{zone.ID, zone.Name, zone.Provider, zone.AccessID, zone.ZoneID, zone.Enabled && zone.Present}
}

func openDDNSProvider(app core.App, zone *dnscatalog.Domain) (dns.Provider, error) {
	access, err := repository.NewAccessRepositoryFor(app).GetById(context.Background(), zone.AccessID)
	if err != nil || access.Provider != zone.Provider {
		return nil, errors.New("DNS catalog credential is unavailable")
	}
	provider, err := dnsmanagement.Open(access, false, app)
	if err != nil {
		return nil, errors.New("could not open DNS catalog credential")
	}
	return provider, nil
}

func registerDDNSBindingCommands(root *cobra.Command, app core.App) {
	fleet := ddnsfleet.New(func(_ context.Context, provider, accessID, zoneID string) (dns.Provider, error) {
		zone, err := dnscatalog.LookupZone(app, provider, accessID, zoneID)
		if err != nil {
			return nil, err
		}
		return openDDNSProvider(app, zone)
	})
	root.AddCommand(
		&cobra.Command{
			Use: "list", Short: "Show DDNS nodes, reported interfaces, and bindings", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				nodes, err := fleet.ListNodes(cmd.Context(), app)
				if err != nil {
					return errors.New("could not list DDNS nodes")
				}
				return json.NewEncoder(cmd.OutOrStdout()).Encode(nodes)
			},
		},
		&cobra.Command{
			Use: "set-enabled NODE_ID true|false", Short: "Enable or pause a node with the server stopped", Args: cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				if args[1] != "true" && args[1] != "false" {
					return errors.New("specify true or false")
				}
				if err := fleet.SetNodeEnabled(cmd.Context(), app, args[0], args[1] == "true"); err != nil {
					if errors.Is(err, ddnsfleet.ErrNodeNotFound) {
						return err
					}
					return errors.New("could not change DDNS node state")
				}
				return nil
			},
		},
	)

	binding := &cobra.Command{Use: "binding", Short: "Manage fixed record bindings with the server stopped"}
	binding.AddCommand(
		&cobra.Command{
			Use: "add NODE_ID CATALOG_ZONE_ID RECORD_ID INTERFACE", Short: "Bind one existing DNS record to a reported interface", Args: cobra.ExactArgs(4),
			RunE: func(cmd *cobra.Command, args []string) error {
				zone, err := dnscatalog.Lookup(app, args[1])
				if err != nil {
					return errors.New("DNS catalog zone is unavailable")
				}
				record, err := fleet.CreateBinding(cmd.Context(), app, args[0], ddnsfleet.BindingInput{
					Provider: zone.Provider, AccessID: zone.AccessID, ZoneID: zone.ZoneID,
					RecordID: args[2], InterfaceName: args[3],
				})
				if err != nil {
					return err
				}
				return json.NewEncoder(cmd.OutOrStdout()).Encode(record)
			},
		},
		&cobra.Command{
			Use: "remove NODE_ID BINDING_ID", Short: "Remove a DDNS binding", Args: cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				return fleet.DeleteBinding(cmd.Context(), app, args[0], args[1])
			},
		},
	)
	root.AddCommand(binding)

	var zonePage int
	zones := &cobra.Command{
		Use: "zones [QUERY]", Short: "Show catalog zone identities", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filter := dnscatalog.Filter{Page: zonePage}
			if len(args) == 1 {
				filter.Search = args[0]
			}
			result, err := dnscatalog.AdminListDomains(cmd.Context(), app, filter, time.Now())
			if err != nil {
				return errors.New("could not list DNS catalog zones")
			}
			output := struct {
				Items []ddnsCatalogZone `json:"items"`
				Total int               `json:"total"`
			}{make([]ddnsCatalogZone, 0, len(result.Items)), result.Total}
			for i := range result.Items {
				output.Items = append(output.Items, ddnsZoneSummary(&result.Items[i]))
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(output)
		},
	}
	zones.Flags().IntVar(&zonePage, "page", 1, "Catalog page number")
	root.AddCommand(zones)

	records := &cobra.Command{Use: "records", Short: "Inspect provider DNS records through the catalog"}
	records.AddCommand(newDDNSRecordListCommand(app, openDDNSProvider))
	root.AddCommand(records)
}

func newDDNSRecordListCommand(app core.App, open func(core.App, *dnscatalog.Domain) (dns.Provider, error)) *cobra.Command {
	var pageNumber int
	var name string
	list := &cobra.Command{
		Use: "list CATALOG_ZONE_ID", Short: "List A and AAAA record identities and addresses", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if pageNumber < 1 || pageNumber > 10000000 {
				return errors.New("invalid records page")
			}
			zone, err := dnscatalog.Lookup(app, args[0])
			if err != nil {
				return errors.New("DNS catalog zone is unavailable")
			}
			provider, err := open(app, zone)
			if err != nil {
				return errors.New("could not open DNS catalog credential")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			filter := strings.TrimSuffix(strings.TrimSpace(name), ".")
			page, err := provider.DNSRecords(ctx, zone.ZoneID, pageNumber, filter)
			if err != nil || page == nil || page.Info.Page != pageNumber || page.Info.Total < len(page.Items) {
				return errors.New("could not list DNS records for the selected zone")
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
				Zone         ddnsCatalogZone `json:"zone"`
				ProviderPage dns.PageInfo    `json:"providerPage"`
				Records      []ddnsRecord    `json:"records"`
			}{ddnsZoneSummary(zone), page.Info, ddnsRecordSummaries(page.Items, filter)})
		},
	}
	list.Flags().IntVar(&pageNumber, "page", 1, "Provider page number")
	list.Flags().StringVar(&name, "name", "", "Exact fully qualified record name")
	return list
}

type ddnsRecord struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Address  string `json:"address"`
	TTL      int    `json:"ttl"`
	Line     string `json:"line,omitempty"`
	Status   string `json:"status,omitempty"`
	Proxied  bool   `json:"proxied"`
	ReadOnly bool   `json:"readOnly"`
}

func ddnsRecordSummaries(rows []dns.DNSRecord, filter string) []ddnsRecord {
	result := make([]ddnsRecord, 0, len(rows))
	for _, record := range rows {
		name := strings.TrimSuffix(record.Name, ".")
		if filter != "" && !strings.EqualFold(filter, name) {
			continue
		}
		address, err := netip.ParseAddr(record.Content)
		if err != nil || address.Zone() != "" {
			continue
		}
		recordType := strings.ToUpper(record.Type)
		switch recordType {
		case "A":
			if !address.Is4() {
				continue
			}
		case "AAAA":
			if !address.Is6() || address.Is4In6() {
				continue
			}
		default:
			continue
		}
		result = append(result, ddnsRecord{
			record.ID, name, recordType, address.String(), record.TTL,
			record.Line, record.Status, record.Proxied, record.ReadOnly,
		})
	}
	return result
}
