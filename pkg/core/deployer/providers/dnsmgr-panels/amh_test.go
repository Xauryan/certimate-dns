package dnsmgrpanels

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// Only the normal sign-in form and server-issued, in-memory browser session
// are used by this fixture. The access record contains a username/password.
const testLoginForm = `<form id="LoginForm" action="/?c=index&amp;a=login" method="POST">
	<input type="text" name="user"><input type="password" name="password">
	<input id="online_set" type="checkbox" name="online_set"><input type="hidden" name="login" value="">
	<button type="submit">Login</button></form>`

func testImportForm(target string) string {
	q := url.Values{"a": {"admin_amssl"}, "c": {"amssl"}, "envs_name": {"web"}, "vhost_name": {target}, "ModuleSort": {"app"}}
	return fmt.Sprintf(`<form method="post" action="/?%s">
		<input type="hidden" name="submit_key_crt" value="y">
		<input type="radio" name="key_input1" value="key_input1">
		<textarea name="key_content1"></textarea>
		<input type="radio" name="crt_input1" value="crt_input1">
		<textarea name="crt_content1"></textarea>
		<button>Install</button></form>`, strings.ReplaceAll(q.Encode(), "&", "&amp;"))
}

type amhScenario struct {
	loginForm, confirmation, csrfScript, result string
	session                                     bool
	form                                        func(string) string
}

func normalAMH() amhScenario {
	return amhScenario{
		loginForm: testLoginForm, session: true, confirmation: "/?amh_token=synthtoken",
		csrfScript: `<script>var OpenCSRF = 'On'; var amh_token = 'synthtoken';</script>`,
		form:       testImportForm, result: `<p id="success">Certificate installed</p>`,
	}
}

func runAMH(t *testing.T, s amhScenario) ([]string, error) {
	t.Helper()
	cert, key := syntheticPair(t)
	var calls []string
	p := testPanel(t, "amh", map[string]any{"username": "operator", "password": "synthetic-password"}, map[string]any{"target": "site.test\nother.test", "environment": "web"}, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error("bad request form")
			return
		}
		if strings.Contains(r.URL.RawQuery, "password") || strings.Contains(r.URL.RawQuery, "PRIVATE") {
			t.Error("query contains credentials")
		}
		a := r.URL.Query().Get("a")
		if a == "login" {
			calls = append(calls, r.Method+" login")
			if r.Method == "GET" {
				if len(r.Cookies()) != 0 {
					t.Error("a session was supplied before login")
				}
				// AMH can start the PHP session when it serves the login form.
				if s.session {
					http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "synthetic-session", Path: "/", Secure: true, HttpOnly: true})
				}
				io.WriteString(w, s.loginForm)
				return
			}
			if r.PostForm.Get("user") != "operator" || r.PostForm.Get("password") != "synthetic-password" || !r.PostForm.Has("login") || r.PostForm.Has("online_set") {
				t.Error("unexpected login form body")
			}
			http.Redirect(w, r, s.confirmation, http.StatusFound)
			return
		}
		target := r.URL.Query().Get("vhost_name")
		calls = append(calls, r.Method+" "+target)
		if r.URL.Query().Get("c") != "amssl" || a != "admin_amssl" || r.URL.Query().Get("envs_name") != "web" || r.URL.Query().Get("ModuleSort") != "app" {
			t.Error("wrong module or environment")
		}
		cookie, err := r.Cookie("PHPSESSID")
		if err != nil || cookie.Value != "synthetic-session" {
			t.Error("missing server-issued session")
		}
		if r.Method == "GET" {
			if s.confirmation == "/?amh_token=synthtoken" && r.URL.Query().Get("amh_token") != "synthtoken" {
				t.Error("lookup omitted session token")
			}
			io.WriteString(w, s.csrfScript+s.form(target))
			return
		}
		if r.PostForm.Get("crt_content1") != cert || r.PostForm.Get("key_content1") != key || r.PostForm.Get("submit_key_crt") != "y" || r.PostForm.Get("key_input1") != "key_input1" || r.PostForm.Get("crt_input1") != "crt_input1" {
			t.Error("wrong certificate import body")
		}
		if strings.Contains(s.csrfScript, "synthtoken") && r.PostForm.Get("amh_token") != "synthtoken" {
			t.Error("omitted issued CSRF token from upload")
		}
		io.WriteString(w, s.result)
	})
	_, err := p.Deploy(context.Background(), cert, key)
	if err != nil {
		for _, s := range []string{"synthtoken", "synthetic-session", "synthetic-password", "PRIVATE KEY", "BEGIN CERTIFICATE"} {
			if strings.Contains(err.Error(), s) {
				t.Fatal("deployment error contains protected data")
			}
		}
	}
	return calls, err
}

func TestAMHBrowserLoginAndPreflight(t *testing.T) {
	for _, csrf := range []bool{true, false} {
		s := normalAMH()
		if !csrf {
			s.confirmation = "/?"
			s.csrfScript = `<script>var OpenCSRF = 'Off';</script>`
		}
		calls, err := runAMH(t, s)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(calls, []string{"GET login", "POST login", "GET site.test", "GET other.test", "POST site.test", "POST other.test"}) {
			t.Fatal("target forms were not checked before writes")
		}
	}
}

func addAMHField(form, field string) string {
	return strings.Replace(form, "</form>", field+"</form>", 1)
}

func TestAMHRejectsUnsupportedLogin(t *testing.T) {
	for _, field := range []string{
		`<input name="VerifyCode">`, `<img src="/?c=verify_code">`, `<input autocomplete="one-time-code">`,
		`<div data-sitekey="challenge"></div>`, `<input name="additional-check">`, `<input type="hidden" name="amh_token" value="">`,
	} {
		t.Run(field, func(t *testing.T) {
			s := normalAMH()
			s.loginForm = addAMHField(s.loginForm, field)
			calls, err := runAMH(t, s)
			if err == nil || !slices.Equal(calls, []string{"GET login"}) {
				t.Fatal("sent credentials to unsupported login form")
			}
		})
	}
	for _, mutate := range []func(*amhScenario){
		func(s *amhScenario) {
			s.loginForm = strings.Replace(s.loginForm, "/?c=index", "https://other.invalid/?c=index", 1)
		},
		func(s *amhScenario) { s.loginForm += testLoginForm },
		func(s *amhScenario) { s.loginForm += `<script>var OpenCSRF='On';</script>` },
	} {
		s := normalAMH()
		mutate(&s)
		calls, err := runAMH(t, s)
		if err == nil || len(calls) != 1 {
			t.Fatal("accepted unverified login form")
		}
	}
	for _, mutate := range []func(*amhScenario){
		func(s *amhScenario) { s.session = false },
		func(s *amhScenario) { s.confirmation = "/?c=index&a=verify_code" },
		func(s *amhScenario) { s.confirmation = "https://other.invalid/" },
	} {
		s := normalAMH()
		mutate(&s)
		calls, err := runAMH(t, s)
		if err == nil || len(calls) != 2 {
			t.Fatal("accepted unverified session")
		}
	}
}

func TestAMHRejectsInvalidTargetBeforeSendingAnyKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		bad  func(string) string
	}{
		{"empty", func(string) string { return "" }},
		{"login", func(string) string { return testLoginForm }},
		{"wrong site", func(string) string { return testImportForm("otherwrong.test") }},
		{"different environment", func(s string) string { return strings.ReplaceAll(s, "envs_name=web", "envs_name=different") }},
		{"missing target", func(s string) string { return strings.ReplaceAll(s, "vhost_name=other.test", "vhost=other.test") }},
		{"ambiguous", func(s string) string { return s + s }},
		{"missing textarea", func(s string) string { return strings.ReplaceAll(s, "key_content1", "key_file") }},
		{"wrong action", func(s string) string { return strings.Replace(s, "admin_amssl", "drop", 1) }},
		{"external action", func(s string) string { return strings.Replace(s, "/?", "https://other.invalid/?", 1) }},
		{"hidden conflict", func(s string) string {
			return addAMHField(s, `<input type="hidden" name="vhost_name" value="wrong.test">`)
		}},
		{"expired token", func(s string) string {
			return addAMHField(s, `<input type="hidden" name="amh_token" value="different">`)
		}},
		{"missing challenge", func(s string) string { return addAMHField(s, `<input name="authorize" required>`) }},
		{"MFA widget", func(s string) string { return s + `<iframe src="/auth/2fa"></iframe>` }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := normalAMH()
			s.form = func(target string) string {
				f := testImportForm(target)
				if target == "other.test" {
					return tc.bad(f)
				}
				return f
			}
			calls, err := runAMH(t, s)
			if err == nil || !slices.Equal(calls, []string{"GET login", "POST login", "GET site.test", "GET other.test"}) {
				t.Fatal("failed to preflight every site before the first upload")
			}
		})
	}
	s := normalAMH()
	s.confirmation = "/?"
	s.csrfScript = `<script>var OpenCSRF = 'On';</script>`
	calls, err := runAMH(t, s)
	if err == nil || len(calls) != 3 {
		t.Fatal("accepted a missing CSRF token")
	}
}

func TestAMHRequiresFreshSuccess(t *testing.T) {
	for _, result := range []string{`<p id=error>synthetic-password</p>`, `<p id=success></p>`, `<p id=success>ok</p><p id=error>synthetic-session</p>`, `<p id=success>previous</p>`, testLoginForm + `<p id=success>ok</p>`} {
		s := normalAMH()
		s.form = func(target string) string { return testImportForm(target) + `<p id=success>previous</p>` }
		s.result = result
		calls, err := runAMH(t, s)
		if err == nil || len(calls) != 5 || !strings.Contains(err.Error(), "0 of 2") {
			t.Fatal("unconfirmed upload was counted as success")
		}
	}
}

func TestAMHImportModeControls(t *testing.T) {
	for _, tc := range []struct {
		name, replacement string
		allowed           bool
	}{
		{"radio alternatives", `<input type="radio" name="key_input1" value="generate"><input type="radio" name="key_input1" value="key_input1"><input type="radio" name="key_input1" value="file">`, true},
		{"single select", `<select name="key_input1"><option value="generate">Generate</option><option value="key_input1">Custom</option></select>`, true},
		{"duplicate chosen value", `<input type="radio" name="key_input1" value="key_input1"><input type="radio" name="key_input1" value="key_input1">`, false},
		{"different control types", `<input type="radio" name="key_input1" value="key_input1"><input type="hidden" name="key_input1" value="generate">`, false},
		{"two selectors", `<select name="key_input1"><option value="generate">Generate</option></select><select name="key_input1"><option value="key_input1">Custom</option></select>`, false},
		{"disabled selected option", `<select name="key_input1"><option disabled value="key_input1">Custom</option></select>`, false},
		{"multi-select", `<select multiple name="key_input1"><option value="key_input1">Custom</option></select>`, false},
		{"disabled group", `<fieldset disabled><input type="radio" name="key_input1" value="key_input1"></fieldset>`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := normalAMH()
			s.form = func(target string) string {
				return strings.Replace(testImportForm(target), `<input type="radio" name="key_input1" value="key_input1">`, tc.replacement, 1)
			}
			calls, err := runAMH(t, s)
			if (err == nil) != tc.allowed || (!tc.allowed && slices.Contains(calls, "POST site.test")) {
				t.Fatal("failed to validate the selected certificate input mode")
			}
		})
	}
}
