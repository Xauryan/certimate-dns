package cloudflare

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

const accountID = "cccccccccccccccccccccccccccccccc"
const tunnelID = "a1111111-2222-3333-4444-555555555555"
const otherTunnelID = "b1111111-2222-3333-4444-555555555555"

func success(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
}

func TestTunnelProvisioningReturnsOnlyRecipientEnvelope(t *testing.T) {
	const secret = "synthetic-connector-value"
	calls := 0
	c := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.Method + " " + r.URL.Path {
		case "POST /accounts/" + accountID + "/cfd_tunnel":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["name"] != "test" || body["config_src"] != "cloudflare" {
				t.Error("missing remote config selection")
			}
			success(w, map[string]string{"id": tunnelID, "name": "test", "token": secret})
		case "GET /accounts/" + accountID + "/cfd_tunnel/" + tunnelID + "/token":
			success(w, secret)
		default:
			t.Error("unexpected endpoint")
		}
	})
	ctx := context.Background()
	created, err := c.CreateTunnel(ctx, accountID, "test")
	out, _ := json.Marshal(created)
	if err != nil || created.ID != tunnelID || strings.Contains(string(out), secret) {
		t.Fatal("tunnel response exposed unexpected data")
	}
	if _, err = c.EncryptedTunnelToken(ctx, accountID, tunnelID, "invalid"); !errors.Is(err, ErrInvalidDNSRequest) || calls != 1 {
		t.Fatal("invalid recipient reached provider")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := c.EncryptedTunnelToken(ctx, accountID, tunnelID, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})))
	if err != nil || strings.Contains(encrypted, secret) {
		t.Fatal("token export failed")
	}
	jwe, err := jose.ParseEncrypted(encrypted, []jose.KeyAlgorithm{jose.RSA_OAEP_256}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := jwe.Decrypt(key)
	if err != nil || string(decoded) != secret {
		t.Fatal("recipient could not decrypt connector token")
	}
}

func TestSaaSPreservesUneditedSettingsAndHidesProviderSecrets(t *testing.T) {
	const marker = "sensitive-synthetic-test-field"
	c := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/zones/"+testZone+"/custom_hostnames/"+tunnelID {
			t.Error("incorrect scope")
			return
		}
		switch r.Method {
		case "GET":
			success(w, map[string]any{"ssl": map[string]any{"type": "dv", "method": "txt", "settings": map[string]string{"min_tls_version": "1.0", "tls_1_3": "on"}, "certificate_authority": "lets_encrypt", "private_key": marker}})
		case "PATCH":
			raw, _ := io.ReadAll(r.Body)
			var patch struct {
				SSL struct {
					Method   string
					Settings map[string]string
					CA       string `json:"certificate_authority"`
				}
			}
			if err := json.Unmarshal(raw, &patch); err != nil || patch.SSL.CA != "lets_encrypt" || patch.SSL.Method != "txt" || patch.SSL.Settings["min_tls_version"] != "1.3" || patch.SSL.Settings["tls_1_3"] != "on" || strings.Contains(string(raw), marker) {
				t.Error("SSL patch did not preserve the site's settings or included secret material")
			}
			success(w, map[string]any{"id": tunnelID, "ssl": map[string]any{"private_key": marker}})
		case "DELETE":
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, marker)
		default:
			t.Error("unexpected method")
		}
	})
	h, err := c.SaveHostname(context.Background(), testZone, tunnelID, HostnameInput{MinTLS: "1.3"})
	out, _ := json.Marshal(h)
	if err != nil || strings.Contains(string(out), marker) {
		t.Fatal("unexpected hostname response")
	}
	err = c.DeleteHostname(context.Background(), testZone, tunnelID)
	var status *ProviderStatusError
	if !errors.As(err, &status) || status.Status != 403 || strings.Contains(err.Error(), marker) {
		t.Fatal("provider errors must be redacted")
	}
}

func TestRouteDeletionVerifiesTunnel(t *testing.T) {
	calls := 0
	c := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" {
			t.Error("provider delete executed for a foreign route")
		}
		success(w, Route{ID: tunnelID, TunnelID: otherTunnelID})
	})
	err := c.DeleteRoute(context.Background(), accountID, tunnelID, "hostname", tunnelID)
	if !errors.Is(err, ErrInvalidDNSRequest) || calls != 1 {
		t.Fatal("cross-tunnel deletion was permitted")
	}
}

func TestIngressDNSReconciliation(t *testing.T) {
	for _, scenario := range []string{"add", "wrong owner", "foreign CNAME", "stale edit", "second path", "delete", "different target", "raced rollback"} {
		t.Run(scenario, func(t *testing.T) {
			const name = "www.example.test"
			target := tunnelID + ".cfargotunnel.com"
			const fallback = `{"service":"http_status:404"}`
			const first = `{"hostname":"www.example.test","path":"/a","service":"https://app.example.test"}`
			const second = `{"hostname":"www.example.test","path":"/b","service":"http://alt.example.test"}`
			ingress := "[" + fallback + "]"
			remove := false
			switch scenario {
			case "second path":
				ingress = "[" + first + "," + second + "," + fallback + "]"
				remove = true
			case "delete", "different target":
				ingress = "[" + first + "," + fallback + "]"
				remove = true
			}
			old := `{"opaque":true,"ingress":` + ingress + `}`
			config := old
			version := int64(2)
			var configWrites, dnsReads, dnsWrites int
			c := localClient(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/zones/" + testZone:
					owner := accountID
					if scenario == "wrong owner" {
						owner = testZone
					}
					success(w, map[string]any{"account": AccountSummary{ID: owner}, "id": testZone, "name": "example.test"})
				case "/accounts/" + accountID + "/cfd_tunnel/" + tunnelID + "/configurations":
					if r.Method == "PUT" {
						configWrites++
						var body struct{ Config json.RawMessage }
						if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
							t.Fatal(err)
						}
						config = string(body.Config)
						version++
						if !strings.Contains(config, `"opaque":true`) {
							t.Error("unknown tunnel setting lost")
						}
					}
					success(w, map[string]any{"version": version, "config": json.RawMessage(config)})
				case "/zones/" + testZone + "/dns_records", "/zones/" + testZone + "/dns_records/" + testRecord:
					switch r.Method {
					case "GET":
						dnsReads++
						if r.URL.Query().Get("name") != name {
							t.Error("missing exact hostname")
						}
						records := []DNSRecord{}
						if remove || scenario == "foreign CNAME" || scenario == "raced rollback" {
							value := target
							if scenario == "foreign CNAME" || scenario == "different target" || scenario == "raced rollback" {
								value = "other.example.test"
							}
							records = append(records, DNSRecord{ID: testRecord, Type: "CNAME", Name: name, Content: value, Proxied: true})
						}
						if scenario == "raced rollback" {
							version++
						}
						success(w, records)
					case "POST":
						dnsWrites++
						var rec DNSRecord
						if err := json.NewDecoder(r.Body).Decode(&rec); err != nil || rec.Name != name || rec.Type != "CNAME" || rec.Content != target || !rec.Proxied || rec.TTL != 1 {
							t.Error("incorrect DNS write")
						}
						success(w, map[string]string{"id": testRecord})
					case "DELETE":
						dnsWrites++
						if r.URL.Path != "/zones/"+testZone+"/dns_records/"+testRecord {
							t.Error("unexpected delete path")
						}
						success(w, map[string]string{"id": testRecord})
					default:
						t.Error("unexpected DNS method")
					}
				default:
					t.Error("unexpected endpoint")
				}
			})
			expected := int64(2)
			if scenario == "stale edit" {
				expected--
			}
			in := IngressChange{Zone: testZone, Version: expected, IngressRule: IngressRule{Hostname: name, Path: "/a", Service: "https://app.example.test"}}
			err := c.ChangeIngress(context.Background(), accountID, tunnelID, in, remove)
			switch scenario {
			case "wrong owner", "stale edit":
				if err == nil || configWrites+dnsWrites+dnsReads != 0 {
					t.Fatal("scope/version violation changed provider state")
				}
			case "foreign CNAME":
				if !errors.Is(err, ErrConfigChanged) || configWrites != 2 || dnsWrites != 0 || strings.Contains(config, name) {
					t.Fatal("failed to restore config after CNAME conflict")
				}
			case "raced rollback":
				if err == nil || configWrites != 1 || dnsWrites != 0 {
					t.Fatal("unsafe rollback over newer config")
				}
			case "second path":
				if err != nil || configWrites != 1 || dnsReads+dnsWrites != 0 || !strings.Contains(config, "/b") {
					t.Fatal("removed DNS needed by another path")
				}
			case "different target":
				if err != nil || configWrites != 1 || dnsReads != 1 || dnsWrites != 0 {
					t.Fatal("deleted a foreign DNS record")
				}
			default:
				if err != nil || configWrites != 1 || dnsWrites != 1 {
					t.Fatalf("reconciliation failed: %v", err)
				}
			}
		})
	}
}
