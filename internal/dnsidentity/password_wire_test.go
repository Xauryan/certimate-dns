package dnsidentity

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdministratorPasswordRealHTTP(t *testing.T) {
	f := newIdentityFixture(t)
	server := httptest.NewServer(f.handler)
	defer server.Close()
	request := func(method, path, token string, body io.Reader, want int, message string) {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", token)
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != want {
			var apiError struct {
				Message string `json:"message"`
			}
			_ = json.Unmarshal(data, &apiError)
			t.Fatalf("%s %s returned HTTP %d %q, expected %d", method, path, res.StatusCode, apiError.Message, want)
		}
		if message != "" && !strings.Contains(string(data), message) {
			t.Fatal("response had unexpected error message")
		}
	}
	const path = adminIdentityAPI + "/password"
	const pass = `{"password":"synthetic-admin-password","newPassword":"synthetic-wire-new-password","passwordConfirm":"synthetic-wire-new-password"}`
	request("POST", path, f.admin, strings.NewReader(pass+`{}`), 400, "Invalid request body.")
	request("POST", path, f.admin, strings.NewReader(strings.TrimSuffix(pass, "}")+`, "unknown":true}`), 400, "Invalid request body.")
	wrong := strings.Replace(pass, "synthetic-admin-password", "synthetic-wrong-password", 1)
	request("POST", path, f.admin, strings.NewReader(wrong), 400, "Invalid current password.")
	oversize := pass + strings.Repeat(" ", proofBodyBytes-len(pass)+1)
	request("POST", path, f.admin, strings.NewReader(oversize), 413, "")
	// Wrapping the reader makes net/http send chunked data without Content-Length.
	request("POST", path, f.admin, io.NopCloser(strings.NewReader(oversize)), 413, "")
	request("GET", adminIdentityAPI+"/security", f.admin, nil, 200, "")
	request("POST", path, f.admin, strings.NewReader(pass), 204, "")
	request("GET", adminIdentityAPI+"/security", f.admin, nil, 401, "")
	const login = "/api/collections/_superusers/auth-with-password"
	request("POST", login, "", strings.NewReader(`{"identity":"root@example.test","password":"synthetic-admin-password"}`), 400, "")
	request("POST", login, "", strings.NewReader(`{"identity":"root@example.test","password":"synthetic-wire-new-password"}`), 200, "")
}
