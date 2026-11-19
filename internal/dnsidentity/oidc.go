package dnsidentity

import (
	"errors"
	"net/url"
	"slices"
	"strings"

	"github.com/certimate-go/certimate/internal/dnsauth"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/security"
)

type oidcSettings struct {
	Enabled      bool   `json:"enabled"`
	DisplayName  string `json:"displayName"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret,omitempty"`
	AuthURL      string `json:"authUrl"`
	TokenURL     string `json:"tokenUrl"`
	UserInfoURL  string `json:"userInfoUrl"`
}

func readOIDC(e *core.RequestEvent) error {
	c, err := e.App.FindCollectionByNameOrId(dnsauth.Members)
	if err != nil {
		return err
	}
	p, ok := c.OAuth2.GetProviderConfig("oidc")
	e.Response.Header().Set("Cache-Control", "no-store")
	return e.JSON(200, oidcSettings{Enabled: c.OAuth2.Enabled && ok, DisplayName: p.DisplayName, ClientID: p.ClientId, AuthURL: p.AuthURL, TokenURL: p.TokenURL, UserInfoURL: p.UserInfoURL})
}

func httpsEndpoint(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == ""
}

func saveOIDC(e *core.RequestEvent) error {
	var s oidcSettings
	if err := decode(e, &s); err != nil {
		return err
	}
	if s.Enabled && (!httpsEndpoint(s.AuthURL) || !httpsEndpoint(s.TokenURL) || !httpsEndpoint(s.UserInfoURL) || strings.TrimSpace(s.ClientID) == "") {
		return e.BadRequestError("Configure HTTPS authorization, token and user-info endpoints and a client ID.", nil)
	}
	err := e.App.RunInTransaction(func(tx core.App) error {
		c, err := tx.FindCollectionByNameOrId(dnsauth.Members)
		if err != nil {
			return err
		}
		p, exists := c.OAuth2.GetProviderConfig("oidc")
		authorityChanged := !exists || p.AuthURL != s.AuthURL || p.TokenURL != s.TokenURL || p.UserInfoURL != s.UserInfoURL || p.ClientId != s.ClientID
		if s.Enabled && s.ClientSecret == "" && authorityChanged {
			return errors.New("client secret required when changing the identity provider")
		}
		if s.Enabled && s.ClientSecret == "" {
			s.ClientSecret = p.ClientSecret
		}
		c.OAuth2.Providers = slices.DeleteFunc(c.OAuth2.Providers, func(p core.OAuth2ProviderConfig) bool { return p.Name == "oidc" })
		if s.Enabled {
			c.OAuth2.Providers = append(c.OAuth2.Providers, core.OAuth2ProviderConfig{Name: "oidc", ClientId: s.ClientID, ClientSecret: s.ClientSecret, DisplayName: s.DisplayName, AuthURL: s.AuthURL, TokenURL: s.TokenURL, UserInfoURL: s.UserInfoURL})
		}
		c.OAuth2.Enabled = len(c.OAuth2.Providers) > 0
		if c.MFA.Enabled && !c.OTP.Enabled && !c.OAuth2.Enabled {
			return errPolicy
		}
		c.AuthToken.Secret = security.RandomString(50)
		if err := tx.Save(c); err != nil {
			return err
		}
		if authorityChanged || !s.Enabled {
			if _, err = tx.DB().Delete(core.CollectionNameExternalAuths, dbx.HashExp{"collectionRef": c.Id, "provider": "oidc"}).Execute(); err != nil {
				return err
			}
		}
		for _, name := range []string{core.CollectionNameMFAs, core.CollectionNameOTPs} {
			if _, err = tx.DB().Delete(name, dbx.HashExp{"collectionRef": c.Id}).Execute(); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return e.BadRequestError("Could not apply OIDC settings. Check the client secret and enabled MFA methods.", nil)
	}
	return e.NoContent(204)
}
