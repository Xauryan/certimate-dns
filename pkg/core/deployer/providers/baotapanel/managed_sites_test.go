package baotapanel

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManagedSitesUseSignedPanelOperations(t *testing.T) {
	for _, tt := range []struct{ kind, path, nameField string }{
		{"docker", "/mod/docker/com/set_ssl", "site_name"},
		{"mail", "/plugin", "domain"},
	} {
		t.Run(tt.kind, func(t *testing.T) {
			const cert, key = "unit-cert", "unit-private-key"
			for _, body := range []string{`{"status":true}`, `{"status":false,"msg":"unit-private-key"}`, `{}`, "unit-private-key"} {
				calls := 0
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					if r.Method != http.MethodPost || r.URL.Path != tt.path || r.PostFormValue(tt.nameField) != "mail.example.test" ||
						r.PostFormValue("key") != key || r.PostFormValue("csr") != cert || r.PostFormValue("request_token") == "" || r.PostFormValue("request_time") == "" {
						t.Error("unexpected signed panel request")
					}
					if tt.kind == "mail" && (r.URL.Query().Get("s") != "set_mail_certificate_multiple" || r.URL.Query().Get("action") != "a" || r.URL.Query().Get("name") != "mail_sys" || r.PostFormValue("act") != "add") {
						t.Error("unexpected mail operation")
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(body))
				}))
				d, err := NewDeployer(&DeployerConfig{ServerUrl: srv.URL, ApiKey: "test-key", AllowInsecureConnections: true, SiteType: tt.kind, SiteNames: []string{"mail.example.test"}})
				if err != nil {
					t.Fatal(err)
				}
				var logs bytes.Buffer
				d.SetLogger(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
				_, err = d.Deploy(context.Background(), cert, key)
				srv.Close()
				if calls != 1 || (err == nil) != (body == `{"status":true}`) {
					t.Fatalf("invalid confirmation or request count %d: %v", calls, err)
				}
				if strings.Contains(logs.String(), key) || (err != nil && strings.Contains(err.Error(), key)) {
					t.Fatal("private material in diagnostics")
				}
			}
		})
	}
}
