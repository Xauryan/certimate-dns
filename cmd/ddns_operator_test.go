package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/dnscatalog"
	"github.com/certimate-go/certimate/internal/domain"
	_ "github.com/certimate-go/certimate/migrations"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type ddnsOperatorDNS struct {
	dns.Provider
	err error
}

func (p ddnsOperatorDNS) Zones(_ context.Context, page int) (*dns.DNSPage[dns.Zone], error) {
	return &dns.DNSPage[dns.Zone]{
		Info: dns.PageInfo{Page: page, Total: 2},
		Items: []dns.Zone{
			{ID: "requested", Name: "example.test", Status: "active"},
			{ID: "unselected", Name: "unrelated.test", Status: "active"},
		},
	}, nil
}

func (p ddnsOperatorDNS) DNSRecords(_ context.Context, _ string, page int, _ string) (*dns.DNSPage[dns.DNSRecord], error) {
	return &dns.DNSPage[dns.DNSRecord]{
		Info: dns.PageInfo{Page: page, Total: 3},
		Items: []dns.DNSRecord{
			{ID: "v4", Name: "vm.example.test.", Type: "A", Content: "172.17.0.1", TTL: 60, Description: "omit metadata"},
			{ID: "v6", Name: "vm.example.test", Type: "AAAA", Content: "2001:db8::1", TTL: 300},
			{ID: "txt", Name: "vm.example.test", Type: "TXT", Content: "omit content"},
		},
	}, p.err
}

func TestDDNSCloudflareImportAndCatalogRecords(t *testing.T) {
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	t.Setenv("CERTIMATE_ADMIN_PASSWORD", "synthetic-operator-test-password")
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.ResetBootstrapState() })
	if err := app.RunAllMigrations(); err != nil {
		t.Fatal(err)
	}

	const token = "synthetic-ddns-api-token"
	importCredential := func(name, zone, input string, provider ddnsOperatorDNS) (ddnsCatalogZone, error) {
		t.Helper()
		var output bytes.Buffer
		cmd := newDDNSCloudflareImportCommand(app, func(credential *domain.Access) (dns.Provider, error) {
			if credential.Provider != "cloudflare" || credential.Config["apiToken"] != token {
				t.Fatal("wrong Cloudflare credential loaded")
			}
			return provider, nil
		})
		cmd.SetArgs([]string{name, "requested", zone})
		cmd.SetIn(strings.NewReader(input))
		cmd.SetOut(&output)
		cmd.SetErr(&output)
		cmd.SilenceUsage = true
		err := cmd.ExecuteContext(t.Context())
		if strings.Contains(output.String(), token) || (err != nil && strings.Contains(err.Error(), token)) {
			t.Fatal("command leaked a token")
		}
		var result ddnsCatalogZone
		if err == nil {
			if err := json.Unmarshal(output.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
		}
		return result, err
	}
	if _, err := importCredential("mismatch", "invalid.test", token, ddnsOperatorDNS{}); !errors.Is(err, errDDNSZoneMismatch) {
		t.Fatalf("expected zone-identity mismatch, got %v", err)
	}
	if _, err := importCredential("unreadable", "example.test", token, ddnsOperatorDNS{err: errors.New(token)}); err == nil {
		t.Fatal("credential without read access was persisted")
	}
	if _, err := importCredential("multiline", "example.test", token+"\nextra", ddnsOperatorDNS{}); err == nil {
		t.Fatal("multiple lines of input were accepted")
	}
	zone, err := importCredential("operator test", "EXAMPLE.TEST.", token+"\r\n", ddnsOperatorDNS{})
	if err != nil || zone.ID == "" || zone.ZoneID != "requested" || zone.Name != "example.test" || !zone.Available {
		t.Fatalf("wrong imported zone result %+v: %v", zone, err)
	}
	if _, err := importCredential("operator test", "example.test", token, ddnsOperatorDNS{}); err == nil {
		t.Fatal("duplicate credential name was accepted")
	}
	accounts, err := app.FindRecordsByFilter("access", "provider='cloudflare'", "", 0, 0)
	if err != nil || len(accounts) != 1 {
		t.Fatalf("expected one saved access, got %d: %v", len(accounts), err)
	}
	zones, err := dnscatalog.AdminListDomains(t.Context(), app, dnscatalog.Filter{Page: 1}, time.Now())
	if err != nil || zones.Total != 1 || zones.Items[0].ID != zone.ID {
		t.Fatalf("unexpected catalog import count %d: %v", zones.Total, err)
	}
	var records bytes.Buffer
	cmd := newDDNSRecordListCommand(app, func(_ core.App, selected *dnscatalog.Domain) (dns.Provider, error) {
		if selected.ZoneID != zone.ZoneID || selected.AccessID != zone.AccessID {
			t.Fatal("wrong provider zone selected")
		}
		return ddnsOperatorDNS{}, nil
	})
	cmd.SetOut(&records)
	cmd.SetArgs([]string{zone.ID, "--name", "VM.Example.Test."})
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	var listed struct {
		Records []ddnsRecord
	}
	if err := json.Unmarshal(records.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Records) != 2 || listed.Records[0].ID != "v4" || listed.Records[1].Address != "2001:db8::1" ||
		strings.Contains(records.String(), "omit") {
		t.Fatal("DNS record output included unexpected records or metadata")
	}
}
