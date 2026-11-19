package dnsmgrpanels

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/html"
)

var (
	amhEnvironment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	// AMH 7.3 header.php exposes the same session token supplied on login.
	amhCSRFSetting  = regexp.MustCompile(`\bvar\s+OpenCSRF\s*=\s*['"](On|Off)['"]`)
	amhTokenSetting = regexp.MustCompile(`\bvar\s+amh_token\s*=\s*['"]([A-Za-z0-9]+)['"]`)
)

func amhAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func amhText(n *html.Node) string {
	var b strings.Builder
	for text := range n.Descendants() {
		if text.Type == html.TextNode {
			b.WriteString(text.Data)
		}
	}
	return strings.TrimSpace(b.String())
}

type amhPage struct {
	forms                            []*html.Node
	token                            string
	csrfEnabled, interactive, failed bool
	success                          string
}

func parseAMHPage(body string) (amhPage, error) {
	var page amhPage
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return page, errors.New("invalid AMH panel page")
	}
	for n := range doc.Descendants() {
		if n.Type != html.ElementNode {
			continue
		}
		switch n.Data {
		case "base":
			if amhAttr(n, "href") != "" {
				return page, errors.New("AMH rewrote the form base address")
			}
		case "form":
			page.forms = append(page.forms, n)
		case "script":
			script := amhText(n)
			if setting := amhCSRFSetting.FindStringSubmatch(script); len(setting) > 0 && setting[1] == "On" {
				page.csrfEnabled = true
			}
			if setting := amhTokenSetting.FindStringSubmatch(script); len(setting) > 0 {
				if page.token != "" && page.token != setting[1] {
					return page, errors.New("conflicting AMH session tokens")
				}
				page.token = setting[1]
			}
		case "p":
			switch amhAttr(n, "id") {
			case "success":
				page.success = amhText(n)
			case "error":
				page.failed = true
			}
		}

		// Check rendered controls and challenge widgets, excluding script text.
		// The vendor login script references the optional captcha even when off.
		for _, a := range n.Attr {
			switch a.Key {
			case "data-sitekey":
				page.interactive = true
			case "name", "id", "class", "src", "action", "autocomplete":
				v := strings.ToLower(a.Val)
				for _, marker := range []string{"verifycode", "verify_code", "code_img", "captcha", "turnstile", "two-factor", "two_factor", "twofactor", "one-time", "totp", "otp", "2fa", "mfa", "webauthn"} {
					if strings.Contains(v, marker) {
						page.interactive = true
					}
				}
			}
		}
	}
	return page, nil
}

type amhControl struct {
	tag, kind, value string
	options          []string
}

func amhHasAttr(n *html.Node, name string) bool {
	for _, a := range n.Attr {
		if a.Key == name {
			return true
		}
	}
	return false
}

func amhDisabled(n *html.Node) bool {
	if amhHasAttr(n, "disabled") {
		return true
	}
	for a := range n.Ancestors() {
		if (a.Data == "fieldset" || a.Data == "optgroup") && amhHasAttr(a, "disabled") {
			return true
		}
	}
	return false
}

func amhChoice(fields []amhControl, expected string) bool {
	var choices []string
	if len(fields) == 1 && fields[0].tag == "select" {
		choices = fields[0].options
	} else if len(fields) == 1 && fields[0].tag == "input" && (fields[0].kind == "hidden" || fields[0].kind == "checkbox") {
		return fields[0].value == expected
	} else {
		for _, c := range fields {
			if c.tag != "input" || c.kind != "radio" {
				return false
			}
			choices = append(choices, c.value)
		}
	}
	seen := make(map[string]bool)
	for _, v := range choices {
		if seen[v] {
			return false
		}
		seen[v] = true
	}
	return seen[expected]
}

func amhControls(form *html.Node) (map[string][]amhControl, error) {
	controls := make(map[string][]amhControl)
	for n := range form.Descendants() {
		if n.Type != html.ElementNode || !slices.Contains([]string{"input", "button", "textarea", "select"}, n.Data) {
			continue
		}
		for _, a := range n.Attr {
			switch a.Key {
			case "form", "formaction", "formmethod":
				return nil, errors.New("unsupported AMH form override")
			}
		}
		name := amhAttr(n, "name")
		if name == "" {
			continue
		}
		if amhDisabled(n) {
			continue
		}
		c := amhControl{tag: n.Data, kind: strings.ToLower(amhAttr(n, "type")), value: amhAttr(n, "value")}
		if n.Data == "select" {
			if amhHasAttr(n, "multiple") {
				return nil, errors.New("unsupported multi-valued AMH selector")
			}
			for opt := range n.Descendants() {
				if opt.Type == html.ElementNode && opt.Data == "option" && !amhDisabled(opt) {
					value := amhAttr(opt, "value")
					if !amhHasAttr(opt, "value") {
						value = amhText(opt)
					}
					c.options = append(c.options, value)
				}
			}
		}
		controls[name] = append(controls[name], c)
	}
	return controls, nil
}

func amhAction(form *html.Node, page *url.URL) (*url.URL, error) {
	if !strings.EqualFold(amhAttr(form, "method"), "post") {
		return nil, errors.New("AMH form does not use POST")
	}
	u, err := page.Parse(amhAttr(form, "action"))
	if err != nil || u.User != nil || u.Fragment != "" || u.Scheme != "https" || !strings.EqualFold(u.Host, page.Host) || u.EscapedPath() != page.EscapedPath() {
		return nil, errors.New("unexpected AMH form action")
	}
	return u, nil
}

func (p *panel) amhLogin(ctx context.Context) (string, error) {
	query := url.Values{"c": {"index"}, "a": {"login"}}
	pageURL := p.endpoint("/", query)
	res, err := p.call(ctx, "/", query, nil, "")
	if err != nil {
		return "", err
	}
	page, err := parseAMHPage(res.body)
	if err != nil {
		return "", err
	}
	if res.status != http.StatusOK || page.interactive || page.failed || len(page.forms) != 1 || amhAttr(page.forms[0], "id") != "LoginForm" {
		return "", errors.New("AMH password login form is missing or requires interactive verification")
	}
	action, err := amhAction(page.forms[0], pageURL)
	if err != nil {
		return "", err
	}
	values, err := url.ParseQuery(action.RawQuery)
	if err != nil || values.Encode() != query.Encode() {
		return "", errors.New("unexpected AMH login action")
	}
	controls, err := amhControls(page.forms[0])
	if err != nil {
		return "", err
	}
	form := url.Values{"user": {p.username}, "password": {p.password}, "login": {""}}
	for name, c := range controls {
		if len(c) != 1 || c[0].tag != "input" {
			return "", errors.New("unsupported AMH login form")
		}
		switch name {
		case "user":
			if c[0].kind != "text" && c[0].kind != "" {
				return "", errors.New("invalid AMH username field")
			}
		case "password":
			if c[0].kind != "password" {
				return "", errors.New("invalid AMH password field")
			}
		case "login":
			if c[0].kind != "hidden" {
				return "", errors.New("invalid AMH login control")
			}
			form.Set("login", c[0].value)
		case "online_set": // leave the persistent login option unchecked
			if c[0].kind != "checkbox" {
				return "", errors.New("unsupported AMH login option")
			}
		case "amh_token":
			if c[0].kind != "hidden" || c[0].value == "" {
				return "", errors.New("invalid AMH login token")
			}
			form.Set("amh_token", c[0].value)
		default:
			return "", errors.New("AMH login requires an additional verification step")
		}
	}
	if len(controls["user"]) != 1 || len(controls["password"]) != 1 || len(controls["login"]) != 1 {
		return "", errors.New("incomplete AMH login form")
	}
	if page.csrfEnabled {
		token := form.Get("amh_token")
		if token == "" {
			token = page.token
		}
		if token == "" || (page.token != "" && token != page.token) {
			return "", errors.New("AMH login requires a consistent session CSRF token")
		}
		form.Set("amh_token", token)
	}
	res, err = p.call(ctx, "/", query, form, pageURL.String())
	if err != nil {
		return "", err
	}
	if res.status != http.StatusFound || res.location == nil || res.location.EscapedPath() != pageURL.EscapedPath() {
		return "", errors.New("AMH login was not confirmed")
	}
	values, err = url.ParseQuery(res.location.RawQuery)
	if err != nil {
		return "", errors.New("invalid AMH login confirmation")
	}
	for key, v := range values {
		if len(v) != 1 || (key != "amh_token" && !(key == "c" && v[0] == "index")) || v[0] == "" {
			return "", errors.New("AMH login requires another step")
		}
	}
	for _, cookie := range p.client.Jar.Cookies(pageURL) {
		if cookie.Name == "PHPSESSID" && cookie.Value != "" {
			return values.Get("amh_token"), nil
		}
	}
	return "", errors.New("AMH did not issue a session cookie")
}

func (p *panel) amhTarget(target string) url.Values {
	return url.Values{"c": {"amssl"}, "a": {"admin_amssl"}, "envs_name": {p.environment}, "vhost_name": {target}, "ModuleSort": {"app"}}
}

type amhImport struct {
	query, form     url.Values
	previousSuccess string
}

// The module can expose multiple operations on one page. Match the import
// controls and require the form itself to identify this environment and vhost.
func (p *panel) amhImportForm(ctx context.Context, target, token string) (*amhImport, error) {
	lookup := p.amhTarget(target)
	if token != "" {
		lookup.Set("amh_token", token)
	}
	res, err := p.call(ctx, "/", lookup, nil, "")
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK {
		return nil, errors.New("AMH did not return the target certificate form")
	}
	page, err := parseAMHPage(res.body)
	if err != nil {
		return nil, err
	}
	if page.interactive || page.failed {
		return nil, errors.New("AMH target requires verification or is unavailable")
	}
	pageURL := p.endpoint("/", lookup)
	var result *amhImport
	for _, f := range page.forms {
		if amhAttr(f, "id") == "LoginForm" {
			return nil, errors.New("AMH session is no longer authenticated")
		}
		// Skip unrelated controls elsewhere on a module page.
		candidate := false
		for n := range f.Descendants() {
			if n.Type == html.ElementNode && (amhAttr(n, "name") == "key_content1" || amhAttr(n, "name") == "crt_content1") {
				candidate = true
				break
			}
		}
		if !candidate {
			continue
		}
		if result != nil {
			return nil, errors.New("ambiguous AMH certificate form")
		}
		action, err := amhAction(f, pageURL)
		if err != nil {
			return nil, err
		}
		query, err := url.ParseQuery(action.RawQuery)
		if err != nil {
			return nil, errors.New("invalid AMH certificate form action")
		}
		controls, err := amhControls(f)
		if err != nil {
			return nil, err
		}
		for _, name := range []string{"key_content1", "crt_content1"} {
			c := controls[name]
			if len(c) != 1 || c[0].tag != "textarea" {
				return nil, errors.New("AMH certificate import area is missing")
			}
		}
		post := url.Values{}
		submit := controls["submit_key_crt"]
		if len(submit) != 1 || submit[0].value != "y" ||
			!(submit[0].tag == "input" && (submit[0].kind == "hidden" || submit[0].kind == "submit") ||
				submit[0].tag == "button" && (submit[0].kind == "" || submit[0].kind == "submit")) {
			return nil, errors.New("unexpected AMH certificate submit control")
		}
		post.Set("submit_key_crt", "y")
		for _, name := range []string{"key_input1", "crt_input1"} {
			if !amhChoice(controls[name], name) {
				return nil, errors.New("unknown or ambiguous AMH input mode")
			}
			post.Set(name, name)
		}
		// Accept explicit action parameters or matching hidden target fields.
		// An empty action alone inherits the GET address and cannot distinguish
		// a provider that silently returned the default site's form.
		targets := p.amhTarget(target)
		explicit, err := url.Parse(amhAttr(f, "action"))
		if err != nil {
			return nil, errors.New("invalid AMH form action")
		}
		for field, v := range targets {
			value := v[0]
			c := controls[field]
			if len(c) > 0 {
				if len(c) != 1 || c[0].kind != "hidden" || c[0].value != value {
					return nil, errors.New("AMH certificate form belongs to another target")
				}
				post.Set(field, value)
			}
			if q, ok := query[field]; ok && (len(q) != 1 || q[0] != value) {
				return nil, errors.New("AMH certificate action belongs to another target")
			}
			if field != "ModuleSort" && len(c) == 0 && query.Get(field) == "" {
				return nil, errors.New("AMH form does not identify the deployment target")
			}
			if (field == "envs_name" || field == "vhost_name") && len(c) == 0 && explicit.Query().Get(field) != value {
				return nil, errors.New("AMH form does not identify the deployment target")
			}
		}
		selectedToken := token
		tokens := []string{page.token}
		if q, ok := query["amh_token"]; ok {
			if len(q) != 1 || q[0] == "" {
				return nil, errors.New("invalid AMH action token")
			}
			tokens = append(tokens, q[0])
		}
		if c := controls["amh_token"]; len(c) > 0 {
			if len(c) != 1 || c[0].kind != "hidden" || c[0].value == "" {
				return nil, errors.New("invalid AMH form token")
			}
			tokens = append(tokens, c[0].value)
		}
		for _, v := range tokens {
			if v == "" {
				continue
			}
			if selectedToken != "" && selectedToken != v {
				return nil, errors.New("AMH session token changed during deployment")
			}
			selectedToken = v
		}
		if page.csrfEnabled && selectedToken == "" {
			return nil, errors.New("AMH requires a session CSRF token")
		}
		if selectedToken != "" {
			post.Set("amh_token", selectedToken)
		}
		for name, fields := range controls {
			if name == "key_content1" || name == "crt_content1" || post.Has(name) {
				continue
			}
			// The import form can also offer a file picker for the same material.
			if len(fields) == 1 && fields[0].tag == "input" && fields[0].kind == "file" {
				continue
			}
			return nil, errors.New("AMH import form requires an unsupported control")
		}
		for field := range query {
			if field != "amh_token" && !targets.Has(field) {
				return nil, errors.New("unknown AMH certificate action")
			}
		}
		result = &amhImport{query: targets, form: post, previousSuccess: page.success}
	}
	if result == nil {
		return nil, errors.New("AMH certificate import form is unavailable")
	}
	return result, nil
}

func (p *panel) deployAMH(ctx context.Context, cert, key string) error {
	token, err := p.amhLogin(ctx)
	if err != nil {
		return err
	}
	forms := make(map[string]*amhImport, len(p.targets))
	for _, target := range p.targets {
		f, err := p.amhImportForm(ctx, target, token)
		if err != nil {
			return err
		}
		forms[target] = f
	}
	return forTargets(p.targets, func(target string) error {
		f := forms[target]
		f.form.Set("key_content1", key)
		f.form.Set("crt_content1", cert)
		res, err := p.call(ctx, "/", f.query, f.form, p.endpoint("/", f.query).String())
		if err != nil {
			return err
		}
		page, err := parseAMHPage(res.body)
		if err != nil {
			return err
		}
		if res.status != http.StatusOK || page.failed || page.interactive || page.success == "" || page.success == f.previousSuccess {
			return errors.New("AMH did not confirm certificate installation")
		}
		for _, form := range page.forms {
			if amhAttr(form, "id") == "LoginForm" {
				return errors.New("AMH session expired during installation")
			}
		}
		return nil
	})
}
