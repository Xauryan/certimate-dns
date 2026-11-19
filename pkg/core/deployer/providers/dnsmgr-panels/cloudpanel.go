package dnsmgrpanels

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/net/html"
)

// CloudPanel issues a separate CSRF token on the login page and on each site's
// import form. Read tokens from the actual input element, regardless of order.
func inputValue(page, name, id string) string {
	t := html.NewTokenizer(strings.NewReader(page))
	for {
		switch t.Next() {
		case html.ErrorToken:
			return ""
		case html.StartTagToken, html.SelfClosingTagToken:
			tag := t.Token()
			if tag.Data != "input" {
				continue
			}
			var value string
			found := false
			for _, a := range tag.Attr {
				if (a.Key == "name" && a.Val == name) || (a.Key == "id" && id != "" && a.Val == id) {
					found = true
				}
				if a.Key == "value" {
					value = a.Val
				}
			}
			if found {
				return value
			}
		}
	}
}

func cloudPanelSuccess(page string) bool {
	t := html.NewTokenizer(strings.NewReader(page))
	success := false
	for {
		switch t.Next() {
		case html.ErrorToken:
			return success
		case html.StartTagToken:
			tag := t.Token()
			for _, a := range tag.Attr {
				if a.Key != "class" {
					continue
				}
				classes := strings.Fields(a.Val)
				if slices.Contains(classes, "alert-danger") || slices.Contains(classes, "alert-warning") {
					return false
				}
				if slices.Contains(classes, "alert-success") {
					success = true
				}
			}
		}
	}
}

func (p *panel) deployCloudPanel(ctx context.Context, cert, key string) error {
	loginURL := p.endpoint("/login", nil)
	page, err := p.call(ctx, "/login", nil, nil, "")
	if err != nil {
		return err
	}
	token := inputValue(page.body, "_csrf_token", "")
	if page.status != http.StatusOK || token == "" {
		return errors.New("CloudPanel login form is unavailable")
	}
	form := url.Values{"userName": {p.username}, "password": {p.password}, "_csrf_token": {token}}
	login, err := p.call(ctx, "/login", nil, form, loginURL.String())
	if err != nil {
		return err
	}
	if login.status < 300 || login.status >= 400 || login.location == nil || len(p.client.Jar.Cookies(loginURL)) == 0 {
		return errors.New("CloudPanel login was not confirmed")
	}
	loc := strings.ToLower(login.location.Path)
	if loc == loginURL.Path || strings.Contains(loc, "2fa") || strings.Contains(loc, "two-factor") || strings.Contains(loc, "totp") {
		return errors.New("CloudPanel session requires interactive authentication")
	}

	return forTargets(p.targets, func(target string) error {
		sitePath := "/site/" + target
		importPath := sitePath + "/certificate/import"
		formURL := p.endpoint(importPath, nil)
		page, err := p.call(ctx, importPath, nil, nil, "")
		if err != nil {
			return err
		}
		token := inputValue(page.body, "site_import_certificate[_token]", "site_import_certificate__token")
		if page.status != http.StatusOK || token == "" {
			return errors.New("CloudPanel certificate import form is unavailable")
		}
		form := url.Values{
			"site_import_certificate[privateKey]": {key}, "site_import_certificate[certificate]": {cert},
			"site_import_certificate[certificateChain]": {""}, "site_import_certificate[submit]": {"Import and Install"},
			"site_import_certificate[_token]": {token},
		}
		res, err := p.call(ctx, importPath, nil, form, formURL.String())
		if err != nil {
			return err
		}
		if (res.status == http.StatusFound || res.status == http.StatusSeeOther) && res.location != nil {
			targetPath := p.endpoint(sitePath, nil).Path
			path := strings.TrimSuffix(res.location.Path, "/")
			if path == targetPath || path == targetPath+"/certificates" || path == p.endpoint("/certificates", nil).Path {
				return nil
			}
		}
		if res.status == http.StatusOK && cloudPanelSuccess(res.body) {
			return nil
		}
		return errors.New("CloudPanel did not confirm certificate installation")
	})
}
