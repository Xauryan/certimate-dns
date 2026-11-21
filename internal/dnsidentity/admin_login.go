package dnsidentity

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/hook"
	"github.com/pocketbase/pocketbase/tools/security"
)

const checkedAdminTOTP = "dns.identity.adminTOTPVerified"
const checkedAdminCaptcha = "dns.identity.adminCaptchaVerified"

func adminCaptchaRequired(app core.App) (bool, error) {
	var required bool
	err := app.DB().NewQuery("SELECT captcha FROM dns_admin_auth_policy WHERE id=1").Row(&required)
	return required, err
}

func installAdminAuth(app core.App) {
	app.Store().Set(adminGuardKey, newLoginGuard())
	app.OnRecordAuthWithPasswordRequest(core.CollectionNameSuperusers).Bind(&hook.Handler[*core.RecordAuthWithPasswordRequestEvent]{
		Id: "dnsAdminPasswordPolicy",
		Func: func(e *core.RecordAuthWithPasswordRequestEvent) error {
			e.Response.Header().Set("Cache-Control", "no-store")
			if err := checkAdminCaptcha(e.RequestEvent); err != nil {
				return err
			}
			attempt, err := reservePassword(e.RequestEvent, adminAttemptScope)
			if err != nil {
				return err
			}
			err = e.Next()
			if e.Record != nil && (err == nil || errors.Is(err, apis.ErrMFA)) {
				attempt.clear(e.App)
			}
			return err
		},
	})
	app.OnRecordAuthWithOTPRequest(core.CollectionNameSuperusers).Bind(&hook.Handler[*core.RecordAuthWithOTPRequestEvent]{
		Id: "dnsAdminEmailOTPPolicy",
		Func: func(e *core.RecordAuthWithOTPRequestEvent) error {
			if err := checkAdminCaptcha(e.RequestEvent); err != nil {
				return err
			}
			return e.Next()
		},
	})
	app.OnRecordAuthWithOAuth2Request(core.CollectionNameSuperusers).Bind(&hook.Handler[*core.RecordAuthWithOAuth2RequestEvent]{
		Id: "dnsAdminOAuth2Policy",
		Func: func(e *core.RecordAuthWithOAuth2RequestEvent) error {
			if err := checkAdminCaptcha(e.RequestEvent); err != nil {
				return err
			}
			return e.Next()
		},
	})
	app.OnRecordAuthRequest(core.CollectionNameSuperusers).Bind(&hook.Handler[*core.RecordAuthRequestEvent]{
		Id: "dnsAdminAuthenticator",
		Func: func(e *core.RecordAuthRequestEvent) error {
			return adminAuthResponse(e)
		},
	})
	app.OnRecordUpdateRequest(core.CollectionNameSuperusers).Bind(&hook.Handler[*core.RecordRequestEvent]{
		Id: "dnsAdminPasswordUpdateProof",
		Func: func(e *core.RecordRequestEvent) error {
			info, err := e.RequestInfo()
			if err != nil {
				return err
			}
			_, changesPassword := info.Body[core.FieldNamePassword]
			if changesPassword || e.Record.TokenKey() != e.Record.Original().TokenKey() {
				active, err := adminTOTPActive(e.App, e.Record.Id)
				if err != nil {
					return e.InternalServerError("Could not check administrator authentication policy.", nil)
				}
				if active {
					return e.ForbiddenError("Use Account Settings to change the password with authenticator verification.", nil)
				}
			}
			return e.Next()
		},
	})
}

func checkAdminCaptcha(e *core.RequestEvent) error {
	required, err := adminCaptchaRequired(e.App)
	if err != nil {
		return e.InternalServerError("Could not check administrator authentication policy.", nil)
	}
	if required {
		g, ok := e.App.Store().Get(adminGuardKey).(*loginGuard)
		if !ok {
			return e.InternalServerError("Sign-in is unavailable.", nil)
		}
		if err := g.verifyCaptcha(e); err != nil {
			return err
		}
	}
	e.Set(checkedAdminCaptcha, true)
	return nil
}

// adminAuthGate lets PocketBase finish its native authentication checks and
// deliver a native MFA challenge. It discards successful native responses
// until the administrator proves possession of their enrolled authenticator.
type adminAuthGate struct {
	http.ResponseWriter
	status int
}

func (g *adminAuthGate) WriteHeader(status int) {
	if g.status != 0 {
		return
	}
	g.status = status
	if status == http.StatusUnauthorized {
		g.ResponseWriter.WriteHeader(status)
	}
}

func (g *adminAuthGate) Write(p []byte) (int, error) {
	if g.status == 0 {
		g.WriteHeader(http.StatusOK)
	}
	if g.status != http.StatusUnauthorized {
		return len(p), nil
	}
	return g.ResponseWriter.Write(p)
}

func adminAuthResponse(e *core.RecordAuthRequestEvent) error {
	e.Response.Header().Set("Cache-Control", "no-store")
	if e.Get(checkedAdminTOTP) == e.Record.Id {
		return e.Next()
	}
	active, err := adminTOTPActive(e.App, e.Record.Id)
	if err != nil {
		return e.InternalServerError("Could not check administrator authentication policy.", nil)
	}
	if e.AuthMethod == "" {
		// Refresh renews an existing authenticated session. Impersonation can
		// issue a new token and must not replace authenticator verification.
		if active && (e.Auth == nil || e.Auth.Id != e.Record.Id || e.Request.PathValue("id") != "") {
			return e.ForbiddenError("Authenticator-protected administrators cannot be impersonated.", nil)
		}
		return e.Next()
	}
	if e.Get(checkedAdminCaptcha) != true {
		if err := checkAdminCaptcha(e.RequestEvent); err != nil {
			return err
		}
	}
	if !active {
		return e.Next()
	}
	// Clear the provider metadata before it can contain credentials from an
	// administrator-authentication provider.
	e.Meta = nil
	gate := &adminAuthGate{ResponseWriter: e.Response}
	e.Response = gate
	defer func() { e.Response = gate.ResponseWriter }()
	err = e.Next()
	e.Response = gate.ResponseWriter
	if err != nil || gate.status == http.StatusUnauthorized {
		return err
	}
	if gate.status != http.StatusOK {
		return e.InternalServerError("Could not check native administrator authentication.", nil)
	}

	challenge := security.RandomString(48)
	res, err := e.App.DB().NewQuery(`UPDATE dns_admin_totp SET challenge={:hash},challenge_expires={:expires},
		challenge_source={:source}, fingerprint={:fingerprint} WHERE admin={:admin}`).Bind(dbx.Params{
		"hash": digest(challenge), "expires": time.Now().Add(3 * time.Minute).Unix(),
		"source": digest(e.RealIP()), "fingerprint": sessionFingerprint(e.Record), "admin": e.Record.Id,
	}).Execute()
	if err != nil {
		return e.InternalServerError("Could not start authenticator verification.", nil)
	}
	if rows, err := res.RowsAffected(); err != nil || rows != 1 {
		return e.BadRequestError("Sign-in state changed. Start again.", nil)
	}
	return e.JSON(http.StatusUnauthorized, map[string]string{"totpId": challenge})
}

func verifyAdminLogin(e *core.RequestEvent) error {
	e.Response.Header().Set("Cache-Control", "no-store")
	var input struct {
		ID   string `json:"totpId"`
		Code string `json:"code"`
	}
	if err := decode(e, &input, proofBodyBytes); errors.Is(err, apis.ErrRequestEntityTooLarge) {
		return err
	} else if err != nil || len(input.ID) != 48 {
		return e.BadRequestError("Invalid authenticator challenge.", nil)
	}
	var verified *core.Record
	err := e.App.RunInTransaction(func(tx core.App) error {
		now := time.Now()
		var row adminFactor
		err := tx.DB().NewQuery(`SELECT admin,seed,fingerprint,last_step,tries,tries_expires FROM dns_admin_totp
			WHERE challenge={:hash} AND challenge_expires>={:now} AND challenge_source={:source}`).
			Bind(dbx.Params{"hash": digest(input.ID), "now": now.Unix(), "source": digest(e.RealIP())}).One(&row)
		if err != nil {
			return err
		}
		r, err := tx.FindRecordById(core.CollectionNameSuperusers, row.Admin)
		if err != nil {
			return err
		}
		if sessionFingerprint(r) != row.Fingerprint {
			return errFactor
		}
		valid, err := row.consume(tx, input.Code, now)
		if err != nil || !valid {
			return err
		}
		err = clearAdminChallenge(tx, row.Admin)
		if err == nil {
			verified = r
		}
		return err
	})
	if err != nil && !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, errFactor) {
		return e.InternalServerError("Could not check the authenticator challenge.", nil)
	}
	if verified == nil {
		return e.BadRequestError("Invalid or expired authenticator challenge.", nil)
	}
	e.Set(checkedAdminTOTP, verified.Id)
	// The native password/OTP/OAuth2 policy, including native MFA, completed
	// on the request that issued this challenge.
	return apis.RecordAuthResponse(e, verified, "", nil)
}
