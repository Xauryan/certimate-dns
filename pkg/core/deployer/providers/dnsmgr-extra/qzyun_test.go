package dnsmgrextra

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

type qzyunTransport func(*http.Request) (*http.Response, error)

func (f qzyunTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

const testDocumentID = "abcdef0123456789abcdef01"
const testHostID = "abcdef0123456789abcdef02"

var testQzyunActions = map[string]string{
	"login": "11111111111111111111111111111111", "addCertificateAction": "22222222222222222222222222222222",
	"updateCertificateAction": "33333333333333333333333333333333", "bindDomainCdnServer": "44444444444444444444444444444444",
}

func testQzyunPage(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	raw := "4:" + string(b) + "\n"
	p1, _ := json.Marshal([]any{1, raw[:len(raw)/2]})
	p2, _ := json.Marshal([]any{1, raw[len(raw)/2:]})
	return `<script src="https://other.example.test/bad.js"></script><script src="/_next/static/app.js"></script><script>self.__next_f.push(` + string(p1) + `)</script><script>self.__next_f.push(` + string(p2) + `)</script>`
}

func TestQzyunActions(t *testing.T) {
	for _, tc := range []struct {
		title                        string
		target                       string
		newCertificate, alreadyBound bool
		want                         []string
	}{
		{"add and bind", "mycert", true, false, []string{"login", "addCertificateAction", "bindDomainCdnServer"}},
		{"update known document", testDocumentID, false, false, []string{"login", "updateCertificateAction", "bindDomainCdnServer"}},
		{"update already bound", "mycert", false, true, []string{"login", "updateCertificateAction"}},
	} {
		t.Run(tc.title, func(t *testing.T) {
			var actions []string
			exists := !tc.newCertificate
			client := http.Client{Transport: qzyunTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Scheme != "https" || r.URL.Host != "panel.qzyun.cn" {
					t.Fatal("non-provider request")
				}
				headers := http.Header{}
				status := 200
				body := ""
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/login":
					body = testQzyunPage(t, []any{"login"})
				case r.Method == http.MethodGet && r.URL.Path == "/_next/static/app.js":
					for action, id := range testQzyunActions {
						body += fmt.Sprintf(`(0,m.createServerReference)("%s",c,void 0,f,"%s");`, id, action)
					}
				case r.Method == http.MethodGet && r.URL.Path == "/certificate":
					if c, err := r.Cookie("session"); err != nil || c.Value != "sample-session" {
						t.Fatal("missing session cookie")
					}
					var records []map[string]any
					if exists {
						record := map[string]any{"name": "mycert", "id": 123, "documentId": testDocumentID, "startTime": 1234, "privateKey": "synthetic", "content": "synthetic"}
						if tc.alreadyBound {
							record["cdnDomains"] = []map[string]any{{"domain": "example.test"}}
						}
						records = append(records, record)
					} else {
						records = []map[string]any{}
					}
					body = testQzyunPage(t, map[string]any{"certificates": records})
				case r.Method == http.MethodGet && r.URL.Path == "/cdn/domain/example.test":
					body = testQzyunPage(t, map[string]any{"id": 321, "documentId": testHostID, "domain": "example.test"})
				case r.Method == http.MethodPost:
					if r.Header.Get("Accept") != "text/x-component" || r.Header.Get("Next-Router-State-Tree") != qzyunRouterState {
						t.Fatal("incorrect action headers")
					}
					if err := r.ParseMultipartForm(1 << 20); err != nil {
						t.Fatal(err)
					}
					action := ""
					for name, id := range testQzyunActions {
						if r.Header.Get("Next-Action") == id {
							action = name
						}
					}
					actions = append(actions, action)
					form := func(k string) string { return r.FormValue(k) }
					switch action {
					case "login":
						if r.URL.Path != "/login" || form("1_email") != "user@example.test" || form("1_password") != "sample-password" {
							t.Fatal("incorrect login request")
						}
						status = http.StatusSeeOther
						headers.Set("Set-Cookie", "session=sample-session; Path=/; Secure")
						headers.Set("Location", "https://other.example.test/never-follow")
					case "addCertificateAction":
						if exists || form("1_certificateName") != "mycert" || form("1_privateKey") != "sample-key" || form("1_serverCertificate") != "sample-cert" {
							t.Fatal("incorrect add request")
						}
						exists = true
					case "updateCertificateAction":
						if !exists || form("1_certDocumentId") != testDocumentID || form("1_privateKey") != "sample-key" || form("1_serverCertificate") != "sample-cert" {
							t.Fatal("incorrect update request")
						}
					case "bindDomainCdnServer":
						if form("1_Id") != "321" || form("1_documentId") != testHostID || form("1_CertificateDocumentId") != testDocumentID || form("1_CertificateName") != "mycert" || form("1_domainName") != "example.test" || form("1_PrivateKey") != "sample-key" {
							t.Fatal("incorrect binding request")
						}
					default:
						t.Fatal("unexpected action")
					}
					body = "0:[]\n1:{\"success\":true,\"message\":\"done\"}\n"
				default:
					t.Fatal("unexpected Qzyun operation")
				}
				return &http.Response{Request: r, StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			res, err := deployQzyun(context.Background(), &client, "user@example.test", "sample-password", tc.target, "example.test", "sample-cert", "sample-key")
			if err != nil {
				t.Fatal(err)
			}
			if res.ExtendedData["documentId"] != testDocumentID || !reflect.DeepEqual(actions, tc.want) {
				t.Errorf("unexpected result or actions: %v", actions)
			}
		})
	}
}

func TestQzyunAmbiguousCertificates(t *testing.T) {
	address, _ := url.Parse(qzyunOrigin + "/certificate")
	body := testQzyunPage(t, []any{
		map[string]any{"name": "mycert", "documentId": testDocumentID, "content": "synthetic"},
		map[string]any{"name": "mycert", "documentId": testHostID, "content": "synthetic"},
	})
	p := qzyunReadPage([]byte(body), address)
	if _, err := p.certificate("mycert"); err == nil {
		t.Fatal("accepted duplicate certificate name")
	}
	if _, err := qzyunReadPage([]byte("<html>"), address).certificate("name"); err == nil {
		t.Fatal("accepted unreadable list")
	}
	drifted := testQzyunPage(t, map[string]any{"layout": "changed", "otherList": []any{}})
	if _, err := qzyunReadPage([]byte(drifted), address).certificate("name"); err == nil {
		t.Fatal("accepted an unrelated page as an empty certificate list")
	}
}

func TestQzyunErrorDoesNotEchoCredential(t *testing.T) {
	client := http.Client{Transport: qzyunTransport(func(r *http.Request) (*http.Response, error) {
		body := ""
		headers := http.Header{}
		switch r.Method {
		case http.MethodGet:
			body = testQzyunPage(t, []any{})
			if strings.HasSuffix(r.URL.Path, ".js") {
				body = `(0,m.createServerReference)("11111111111111111111111111111111",c,void 0,f,"login");`
			}
		case http.MethodPost:
			body = `1:{"success":false,"error":"sample-password"}`
			headers.Set("Set-Cookie", "tracking=1; Path=/")
		}
		return &http.Response{Request: r, StatusCode: 200, Header: headers, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	_, err := deployQzyun(context.Background(), &client, "user@example.test", "sample-password", "mycert", "", "sample-cert", "sample-key")
	if err == nil || strings.Contains(err.Error(), "sample-password") {
		t.Fatal("failed to contain unsuccessful login")
	}
}

func TestQzyunConcurrentAccountCancellation(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	client := http.Client{Transport: qzyunTransport(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-release
		return &http.Response{Request: r, StatusCode: 503, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	go func() {
		_, err := deployQzyun(context.Background(), &client, "user@example.test", "sample", "one", "", "sample", "sample")
		done <- err
	}()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := deployQzyun(ctx, &client, "USER@example.test", "sample", "two", "", "sample", "sample")
	close(release)
	if <-done == nil || err != context.Canceled {
		t.Fatal("concurrent account mutation was not gated")
	}
}
