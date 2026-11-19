// Package dnsidentity manages DNS member sign-in policies and QQ notifications.
package dnsidentity

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	"github.com/pocketbase/pocketbase/tools/security"

	"github.com/certimate-go/certimate/internal/dnsauth"
)

const secretEnv = "CERTIMATE_DNS_QQBOT_SECRET"

var appIDPattern = regexp.MustCompile(`^[0-9]{1,32}$`)
var recipientPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type destination struct {
	Enabled     bool   `db:"enabled" json:"enabled"`
	AppID       string `db:"app_id" json:"appId"`
	OpenID      string `db:"open_id" json:"openId"`
	ConfirmedAt int64  `db:"confirmed_at" json:"confirmedAt"`
}

func getDestination(app core.App) (d destination, err error) {
	err = app.DB().NewQuery(`SELECT enabled, app_id, open_id, confirmed_at FROM dns_qq_notification WHERE id=1`).One(&d)
	return
}

func decode(e *core.RequestEvent, target any) error {
	decoder := json.NewDecoder(e.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return e.BadRequestError("Invalid request body.", nil)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return e.BadRequestError("Invalid request body.", nil)
	}
	return nil
}

// Bind registers management endpoints under the /api group. The webhook is
// separately registered by BindWebhook because Tencent authenticates callbacks.
func Bind(group *router.RouterGroup[*core.RequestEvent]) {
	api := group.Group("/dns-identity").Bind(apis.RequireSuperuserAuth(), apis.BodyLimit(8192))
	bindTOTP(group)
	group.GET("/dns-identity/captcha", serveCaptcha)
	api.GET("/oidc", readOIDC)
	api.PUT("/oidc", saveOIDC)
	api.GET("/qq", func(e *core.RequestEvent) error {
		d, err := getDestination(e.App)
		if err != nil {
			return e.InternalServerError("Could not load QQ destination.", nil)
		}
		e.Response.Header().Set("Cache-Control", "no-store")
		return e.JSON(200, struct {
			destination
			SecretConfigured bool `json:"secretConfigured"`
		}{d, os.Getenv(secretEnv) != ""})
	})
	api.PUT("/qq", func(e *core.RequestEvent) error {
		var input struct {
			Enabled *bool   `json:"enabled"`
			AppID   *string `json:"appId"`
			OpenID  *string `json:"openId"`
		}
		if err := decode(e, &input); err != nil {
			return err
		}
		if input.Enabled == nil || input.AppID == nil || input.OpenID == nil {
			return e.BadRequestError("Provide enabled, appId and openId.", nil)
		}
		enabled, appID, openID := *input.Enabled, *input.AppID, *input.OpenID
		if appID != "" && !appIDPattern.MatchString(appID) || openID != "" && !recipientPattern.MatchString(openID) {
			return e.BadRequestError("Invalid QQ AppID or OpenID.", nil)
		}
		if enabled && (appID == "" || os.Getenv(secretEnv) == "") {
			return e.BadRequestError("Set AppID and the bot secret before enabling notifications.", nil)
		}
		_, err := e.App.DB().NewQuery(`UPDATE dns_qq_notification SET confirmed_at=CASE WHEN app_id={:app} AND open_id={:recipient} THEN confirmed_at ELSE 0 END,
   enabled={:enabled}, app_id={:app}, open_id={:recipient}, bind_hash='', bind_expires=0 WHERE id=1`).Bind(dbx.Params{"app": appID, "recipient": openID, "enabled": enabled}).Execute()
		if err != nil {
			return e.InternalServerError("Could not save QQ destination.", nil)
		}
		e.App.Logger().Info("Updated DNS QQ notification settings", "actor", e.Auth.Id, "enabled", enabled)
		return e.NoContent(204)
	})
	api.POST("/qq/bind", func(e *core.RequestEvent) error {
		d, err := getDestination(e.App)
		if err != nil || !d.Enabled || os.Getenv(secretEnv) == "" {
			return e.BadRequestError("Enable the bot first.", nil)
		}
		code := "bind-" + security.RandomString(16)
		_, err = e.App.DB().NewQuery(`UPDATE dns_qq_notification SET bind_hash={:hash},bind_expires={:expires} WHERE id=1 AND enabled=1 AND app_id={:id}`).Bind(dbx.Params{
			"hash": digest(code), "expires": time.Now().Add(5 * time.Minute).Unix(), "id": d.AppID,
		}).Execute()
		if err != nil {
			return err
		}
		e.Response.Header().Set("Cache-Control", "no-store")
		return e.JSON(200, map[string]string{"code": code})
	})
	api.GET("/member-policy", func(e *core.RequestEvent) error {
		c, err := e.App.FindCollectionByNameOrId(dnsauth.Members)
		if err != nil {
			return e.InternalServerError("Could not read member policy.", nil)
		}
		e.Response.Header().Set("Cache-Control", "no-store")
		providers := make([]string, 0)
		if c.OAuth2.Enabled {
			for _, p := range c.OAuth2.Providers {
				providers = append(providers, p.Name)
			}
		}
		captcha, err := captchaRequired(e.App)
		if err != nil {
			return err
		}
		return e.JSON(200, map[string]any{"captcha": captcha, "mfa": c.MFA.Enabled, "otp": c.OTP.Enabled, "rule": c.MFA.Rule, "providers": providers})
	})
	api.PUT("/member-policy", func(e *core.RequestEvent) error {
		var input struct {
			MFA     *bool `json:"mfa"`
			OTP     *bool `json:"otp"`
			Captcha *bool `json:"captcha"`
		}
		if err := decode(e, &input); err != nil {
			return err
		}
		if input.MFA == nil || input.OTP == nil {
			return e.BadRequestError("Both MFA and email OTP settings are required.", nil)
		}
		err := e.App.RunInTransaction(func(tx core.App) error {
			c, err := tx.FindCollectionByNameOrId(dnsauth.Members)
			if err != nil {
				return err
			}
			if *input.MFA && !*input.OTP && !(c.PasswordAuth.Enabled && c.OAuth2.Enabled && len(c.OAuth2.Providers) > 0) {
				return errPolicy
			}
			if input.Captcha != nil {
				if _, err := tx.DB().Update("dns_login_policy", dbx.Params{"captcha": *input.Captcha}, dbx.HashExp{"id": 1}).Execute(); err != nil {
					return err
				}
			}
			if c.MFA.Enabled == *input.MFA && c.OTP.Enabled == *input.OTP && c.MFA.Rule == "" {
				return nil
			}
			c.OTP.Enabled = *input.OTP
			c.MFA.Enabled = *input.MFA
			c.MFA.Rule = ""
			// Require existing browser/API sessions to authenticate under the new policy.
			c.AuthToken.Secret = security.RandomString(50)
			if err = tx.Save(c); err != nil {
				return err
			}
			for _, name := range []string{core.CollectionNameMFAs, core.CollectionNameOTPs} {
				if _, err = tx.DB().Delete(name, dbx.HashExp{"collectionRef": c.Id}).Execute(); err != nil {
					return err
				}
			}
			return nil
		})
		if errors.Is(err, errPolicy) {
			return e.BadRequestError(errPolicy.Error(), nil)
		}
		if err != nil {
			return e.BadRequestError("Could not apply member authentication policy.", nil)
		}
		e.App.Logger().Info("Updated DNS member authentication policy", "actor", e.Auth.Id, "mfa", *input.MFA, "otp", *input.OTP)
		return e.NoContent(204)
	})
	api.POST("/qq/test", func(e *core.RequestEvent) error {
		d, err := getDestination(e.App)
		if err != nil || !d.Enabled {
			return e.BadRequestError("QQ notifications must be enabled.", nil)
		}
		err = sendQQ(e.Request.Context(), d, os.Getenv(secretEnv), "Certimate DNS 通知测试", qqClient)
		e.App.Logger().Info("Tested DNS QQ notification", "actor", e.Auth.Id, "success", err == nil)
		if err != nil {
			return e.Error(502, "QQ notification delivery failed.", nil)
		}
		return e.NoContent(204)
	})
}

var errPolicy = errors.New("MFA requires at least two enabled sign-in methods.")

func confirm(app core.App, d destination, at time.Time) error {
	_, err := app.DB().NewQuery(`UPDATE dns_qq_notification SET confirmed_at=MAX(confirmed_at, {:ts}) WHERE id=1 AND enabled=1 AND app_id={:app} AND open_id={:recipient}`).Bind(dbx.Params{"ts": at.Unix(), "app": d.AppID, "recipient": d.OpenID}).Execute()
	return err
}
