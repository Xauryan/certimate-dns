package baidu

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

const (
	recordPath    = zonePath + "/example.test/record"
	row           = `{"id":"r1","rr":"@","status":"running","type":"MX","value":"mx.example.test","priority":3,"ttl":300,"line":"ct","description":"previous note"}`
	inventory     = `{"isTruncated":false,"records":[` + row + `]}`
	domainListing = `{"isTruncated":false,"zones":[{"name":"other.example.test","productVersion":"discount"},{"name":"example.test.","status":"running","productVersion":"free"}]}`
)

type exchange struct {
	method, path, query, body, reply string
}

func fixture(t *testing.T, exchanges ...exchange) *provider {
	t.Helper()
	p, err := New(&domain.Access{Config: map[string]any{"accessKeyId": "test-id", "secretAccessKey": "synthetic-value"}})
	if err != nil {
		t.Fatal(err)
	}
	c := p.(*provider)
	c.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		t.Helper()
		if len(exchanges) == 0 {
			t.Fatal("unexpected extra request")
		}
		step := exchanges[0]
		exchanges = exchanges[1:]
		q := r.URL.Query()
		if step.method != "GET" {
			if q.Get("clientToken") == "" {
				t.Fatal("missing idempotency token")
			}
			q.Del("clientToken")
		}
		if r.URL.Scheme != "https" || r.URL.Host != "dns.baidubce.com" || !strings.HasPrefix(r.Header.Get("Authorization"), "bce-auth-v1/test-id/") || r.Header.Get("x-bce-date") == "" {
			t.Fatal("invalid endpoint or signature")
		}
		if r.Method != step.method || r.URL.Path != step.path || q.Encode() != step.query {
			t.Fatalf("unexpected request %s %s %v", r.Method, r.URL.Path, q)
		}
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(r.Body)
		}
		if step.body != "" {
			var got, want any
			if json.Unmarshal(body, &got) != nil || json.Unmarshal([]byte(step.body), &want) != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("unexpected %s body %s", r.Method, body)
			}
		} else if len(body) != 0 {
			t.Fatal("unexpected request payload")
		}
		status := 200
		if step.reply == "denied" {
			status = 403
			step.reply = "synthetic-sensitive-diagnostic"
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(step.reply)), Request: r}, nil
	})
	t.Cleanup(func() {
		if len(exchanges) != 0 {
			t.Errorf("missing %d provider calls", len(exchanges))
		}
	})
	return c
}

func TestZoneDiscoveryAndCreation(t *testing.T) {
	p := fixture(t,
		exchange{"GET", zonePath, "maxKeys=1000", "", `{"isTruncated":true,"nextMarker":"abc+","zones":[{"name":"first.test"}]}`},
		exchange{"GET", zonePath, "marker=abc%2B&maxKeys=1000", "", domainListing},
		exchange{"POST", zonePath, "", `{"name":"example.test"}`, ""},
		exchange{"GET", zonePath, "maxKeys=1000&name=example.test", "", domainListing},
		exchange{"GET", zonePath, "maxKeys=1000&name=example.test", "", domainListing},
	)
	ctx := context.Background()
	zs, err := p.Zones(ctx, 1)
	if err != nil || zs.Info.Total != 3 || zs.Items[2].ID != "example.test" {
		t.Fatal(zs, err)
	}
	z, err := p.CreateZone(ctx, "Example.test.")
	if err != nil || z.ID != "example.test" || z.Status != "running" {
		t.Fatal(z, err)
	}
	d, err := p.ZoneDetails(ctx, z.ID)
	if err != nil || len(d.Lines) != 6 || d.MinTTL != 300 || d.Plan != "free" {
		t.Fatal(d, err)
	}
}

func TestScopedRecordWrites(t *testing.T) {
	ctx := context.Background()
	p := fixture(t,
		exchange{"POST", recordPath, "", `{"rr":"@","line":"ct","ttl":300,"value":"mx.example.test","type":"MX","description":"previous note","priority":3}`, ""},
		exchange{"GET", recordPath, "maxKeys=1000&rr=%40", "", inventory},
		exchange{"GET", recordPath, "id=r1&maxKeys=1000", "", inventory},
		exchange{"PUT", recordPath + "/r1", "", `{"rr":"@","type":"MX","ttl":900,"value":"changed.example.test","priority":3,"description":"previous note"}`, ""},
		exchange{"GET", recordPath, "id=r1&maxKeys=1000", "", inventory},
		exchange{"PUT", recordPath + "/r1", "", `{"rr":"@","type":"MX","ttl":300,"value":"mx.example.test","priority":3,"description":"updated"}`, ""},
		exchange{"GET", recordPath, "id=r1&maxKeys=1000", "", inventory},
		exchange{"PUT", recordPath + "/r1", "disable=", "", ""},
		exchange{"GET", recordPath, "id=r1&maxKeys=1000", "", inventory},
		exchange{"DELETE", recordPath + "/r1", "", "", ""},
	)
	priority := 3
	id, err := p.CreateDNSRecord(ctx, "example.test", dns.RecordInput{Name: "@", Type: "MX", Content: "3 mx.example.test", Priority: &priority, Description: "previous note", Line: "ct", TTL: 300})
	if err != nil || id != "r1" {
		t.Fatal(id, err)
	}
	if _, err = p.PatchDNSRecord(ctx, "example.test", "r1", dns.RecordPatch{Content: "changed.example.test", TTL: 900}); err != nil {
		t.Fatal(err)
	}
	if err = p.SetBatchAttribute(ctx, "example.test", "r1", "remark", "updated"); err != nil {
		t.Fatal(err)
	}
	if err = p.SetBatchAttribute(ctx, "example.test", "r1", "status", "disabled"); err != nil {
		t.Fatal(err)
	}
	if _, err = p.DeleteDNSRecord(ctx, "example.test", "r1"); err != nil {
		t.Fatal(err)
	}
}

func TestIncompleteOrForeignResponseStopsWrites(t *testing.T) {
	ctx := context.Background()
	for name, response := range map[string]string{
		"missing paging flag":   `{"records":[` + row + `]}`,
		"duplicate ID":          `{"isTruncated":false,"records":[` + row + "," + row + `]}`,
		"missing owner":         strings.Replace(inventory, `"rr":"@",`, "", 1),
		"mismatched zone":       strings.Replace(inventory, `"rr":"@"`, `"rr":"@","zone_name":"other.test."`, 1),
		"mismatched full owner": strings.Replace(inventory, `"rr":"@"`, `"name":"elsewhere.test."`, 1),
		"missing next page":     strings.Replace(inventory, "false", "true", 1),
		"missing MX priority":   strings.Replace(inventory, `"priority":3,`, "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			p := fixture(t, exchange{"GET", recordPath, "id=r1&maxKeys=1000", "", response})
			if _, err := p.PatchDNSRecord(ctx, "example.test", "r1", dns.RecordPatch{Content: "new.example.test", TTL: 300}); err == nil {
				t.Fatal("accepted incomplete detail")
			}
		})
	}
	p := fixture(t, exchange{"GET", recordPath, "id=r1&maxKeys=1000", "", `{"isTruncated":true,"nextMarker":"more","records":[` + row + `]}`}, exchange{"GET", recordPath, "id=r1&marker=more&maxKeys=1000", "", "denied"})
	if _, err := p.DeleteDNSRecord(ctx, "example.test", "r1"); err == nil || strings.Contains(err.Error(), "synthetic") {
		t.Fatal("did not discard failed page and upstream diagnostic")
	}
}

func TestInvalidInputDoesNotCallProvider(t *testing.T) {
	p := fixture(t)
	if _, err := New(nil); !errors.Is(err, domain.ErrInvalidParams) {
		t.Fatal(err)
	}
	if _, err := p.DeleteDNSRecord(context.Background(), "example.test", "../r1"); !errors.Is(err, dns.ErrInvalidDNSRequest) {
		t.Fatal(err)
	}
	if _, err := p.CreateDNSRecord(context.Background(), "example.test", dns.RecordInput{Name: "other.test", Type: "TXT", Content: "abc", TTL: 300}); !errors.Is(err, dns.ErrInvalidDNSRequest) {
		t.Fatal(err)
	}
}
