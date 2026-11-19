package dnsmgrpanels

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

func (p *panel) deployKangle(ctx context.Context, cert, key string) error {
	admin := p.provider != "kangle"
	root := "/vhost"
	callback := "/index.php"
	if admin {
		root = p.adminPath
		callback = root + "/index.php"
	}
	loginPath := root + "/index.php"
	if p.secret != "" {
		query := url.Values{"c": {"sso"}, "a": {"hello"}, "url": {p.endpoint(callback, nil).String() + "?"}}
		res, err := p.call(ctx, loginPath, query, nil, "")
		if err != nil {
			return err
		}
		if res.status != http.StatusFound || res.location == nil {
			return errors.New("Kangle SSO challenge failed")
		}
		challenge := res.location.Query().Get("r")
		if challenge == "" || len(p.client.Jar.Cookies(p.endpoint(loginPath, nil))) == 0 {
			return errors.New("Kangle SSO session is incomplete")
		}
		// This MD5 signature is the EasyPanel SSO protocol (not password storage).
		signature := md5.Sum([]byte(challenge + p.username + challenge + p.secret))
		query = url.Values{"c": {"sso"}, "a": {"login"}, "name": {p.username}, "r": {challenge}, "s": {hex.EncodeToString(signature[:])}}
		res, err = p.call(ctx, loginPath, query, nil, "")
		if err != nil {
			return err
		}
		if res.status != http.StatusFound {
			return errors.New("Kangle SSO login failed")
		}
	} else {
		referer := p.endpoint(loginPath, url.Values{"c": {"session"}, "a": {"loginForm"}}).String()
		res, err := p.call(ctx, loginPath, url.Values{"c": {"session"}, "a": {"login"}}, url.Values{"username": {p.username}, "passwd": {p.password}}, referer)
		if err != nil {
			return err
		}
		if res.status != http.StatusFound || len(p.client.Jar.Cookies(p.endpoint("/vhost/", nil))) == 0 {
			return errors.New("Kangle password login failed")
		}
	}
	if p.provider == "kangleadmin-console" {
		return p.kangleUpdate(ctx, loginPath, url.Values{"c": {"security"}, "a": {"ssl"}}, url.Values{"crt": {cert}, "key": {key}})
	}
	if !admin {
		return p.installVhost(ctx, p.targets, cert, key)
	}
	return forTargets(p.targets, func(target string) error {
		res, err := p.call(ctx, loginPath, url.Values{"c": {"vhost"}, "a": {"impLogin"}, "name": {target}}, nil, "")
		if err != nil {
			return err
		}
		vhost := p.endpoint("/vhost", nil)
		if res.status != http.StatusFound || res.location == nil ||
			(res.location.Path != vhost.Path && !strings.HasPrefix(res.location.Path, vhost.Path+"/")) ||
			strings.Contains(strings.ToLower(res.location.Query().Get("a")), "login") {
			return errors.New("Kangle virtual host selection failed")
		}
		return p.installVhost(ctx, p.domains, cert, key)
	})
}

func (p *panel) installVhost(ctx context.Context, domains []string, cert, key string) error {
	res, err := p.call(ctx, "/vhost/", nil, nil, "")
	if err != nil {
		return err
	}
	if res.status != http.StatusOK || len(p.client.Jar.Cookies(p.endpoint("/vhost/", nil))) == 0 {
		return errors.New("Kangle virtual host session is unavailable")
	}
	form := url.Values{"certificate": {cert}, "certificate_key": {key}}
	if len(domains) == 0 {
		return p.kangleUpdate(ctx, "/vhost/", url.Values{"c": {"ssl"}, "a": {"ssl"}}, form)
	}
	return forTargets(domains, func(domain string) error {
		form.Set("domain", domain)
		return p.kangleUpdate(ctx, "/vhost/", url.Values{"c": {"ssl"}, "a": {"domainSsl"}}, form)
	})
}

func (p *panel) kangleUpdate(ctx context.Context, route string, query, form url.Values) error {
	res, err := p.call(ctx, route, query, form, "")
	if err != nil {
		return err
	}
	if res.status != http.StatusOK || !strings.Contains(res.body, "成功") || strings.Contains(res.body, "失败") || strings.Contains(res.body, "未成功") || strings.Contains(res.body, "不成功") {
		return errors.New("Kangle did not confirm certificate installation")
	}
	return nil
}
