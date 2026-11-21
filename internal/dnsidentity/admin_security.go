package dnsidentity

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	"github.com/pocketbase/pocketbase/tools/security"
	"github.com/pquerna/otp/totp"
)

const adminFactorAttempts = 5

type adminFactor struct {
	Admin        string `db:"admin"`
	Seed         string `db:"seed"`
	Fingerprint  string `db:"fingerprint"`
	LastStep     int64  `db:"last_step"`
	Tries        int    `db:"tries"`
	TriesExpires int64  `db:"tries_expires"`
}

func adminTOTPActive(app core.App, id string) (bool, error) {
	var active bool
	err := app.DB().NewQuery("SELECT EXISTS (SELECT 1 FROM dns_admin_totp WHERE admin={:id})").Bind(dbx.Params{"id": id}).Row(&active)
	return active, err
}

// consume requires a fresh authenticator time step and persists failed attempts
// across challenges and account settings. Callers commit a failed comparison.
func (f adminFactor) consume(tx core.App, code string, now time.Time) (bool, error) {
	if f.TriesExpires <= now.Unix() {
		f.Tries = 0
		f.TriesExpires = now.Add(10 * time.Minute).Unix()
	}
	if f.Tries >= adminFactorAttempts {
		return false, nil
	}
	step, err := matchedStep(keyForTOTP(tx), f.Seed, code, now, f.LastStep)
	update := dbx.Params{"last_step": step, "tries": 0, "tries_expires": 0}
	if err != nil {
		update = dbx.Params{"tries": f.Tries + 1, "tries_expires": f.TriesExpires}
	}
	_, updateErr := tx.DB().Update("dns_admin_totp", update, dbx.HashExp{"admin": f.Admin}).Execute()
	return err == nil, updateErr
}

func verifyAdminFactor(tx core.App, id string, code string, required bool) error {
	var f adminFactor
	err := tx.DB().NewQuery(`SELECT admin,seed,last_step,tries,tries_expires FROM dns_admin_totp WHERE admin={:id}`).
		Bind(dbx.Params{"id": id}).One(&f)
	if errors.Is(err, sql.ErrNoRows) {
		if required {
			return errFactor
		}
		return nil
	}
	if err != nil {
		return err
	}
	valid, err := f.consume(tx, code, time.Now())
	if err != nil {
		return err
	}
	if !valid {
		return errFactor
	}
	return nil
}

func bindAdminAuth(api *router.RouterGroup[*core.RequestEvent]) {
	group := api.Group("/dns-identity/admin").Bind(apis.BodyLimit(proofBodyBytes))
	group.BindFunc(func(e *core.RequestEvent) error {
		e.Response.Header().Set("Cache-Control", "no-store")
		return e.Next()
	})
	group.GET("/captcha", func(e *core.RequestEvent) error {
		required, err := adminCaptchaRequired(e.App)
		if err != nil {
			return e.InternalServerError("Could not check administrator authentication policy.", nil)
		}
		return respondCaptcha(e, required, adminGuardKey)
	})
	group.POST("/totp/login", verifyAdminLogin)
	settings := group.Group("").Bind(apis.RequireSuperuserAuth())
	settings.GET("/security", adminSecurity)
	settings.PUT("/policy", setAdminPolicy)
	settings.POST("/password", changeAdminPassword)
	settings.POST("/totp/generate", generateAdminTOTP)
	settings.POST("/totp/bind", bindAdminTOTP)
	settings.POST("/totp/remove", removeAdminTOTP)
}

func adminSecurity(e *core.RequestEvent) error {
	captcha, err := adminCaptchaRequired(e.App)
	if err != nil {
		return err
	}
	active, err := adminTOTPActive(e.App, e.Auth.Id)
	if err != nil {
		return err
	}
	return e.JSON(http.StatusOK, map[string]bool{
		"captcha": captcha, "active": active, "available": len(keyForTOTP(e.App)) == 32,
	})
}

func runAdminOperation(e *core.RequestEvent, password string, operation func(core.App, *core.Record) error) error {
	if !e.Auth.ValidatePassword(password) {
		return e.BadRequestError("Invalid current password.", nil)
	}
	var invalid bool
	err := e.App.RunInTransaction(func(tx core.App) error {
		r, err := tx.FindRecordById(core.CollectionNameSuperusers, e.Auth.Id)
		if err != nil {
			return err
		}
		if sessionFingerprint(r) != sessionFingerprint(e.Auth) {
			return e.UnauthorizedError("Sign-in state changed. Sign in again.", nil)
		}
		err = operation(tx, r)
		invalid = errors.Is(err, errFactor)
		if invalid {
			return nil // keep the failed authenticator attempt
		}
		return err
	})
	if err != nil {
		return err
	}
	if invalid {
		return e.BadRequestError("Invalid, expired or rate-limited authenticator verification.", nil)
	}
	return nil
}

func setAdminPolicy(e *core.RequestEvent) error {
	var input struct {
		Password string `json:"password"`
		Code     string `json:"code"`
		Captcha  *bool  `json:"captcha"`
	}
	if err := decode(e, &input, proofBodyBytes); err != nil {
		return err
	}
	if input.Captcha == nil {
		return e.BadRequestError("Provide the image code setting.", nil)
	}
	err := runAdminOperation(e, input.Password, func(tx core.App, r *core.Record) error {
		if err := verifyAdminFactor(tx, r.Id, input.Code, false); err != nil {
			return err
		}
		_, err := tx.DB().Update("dns_admin_auth_policy", dbx.Params{"captcha": *input.Captcha}, dbx.HashExp{"id": 1}).Execute()
		return err
	})
	if err != nil {
		return err
	}
	e.App.Logger().Info("Updated administrator sign-in policy", "actor", e.Auth.Id, "captcha", *input.Captcha)
	return e.NoContent(http.StatusNoContent)
}

func changeAdminPassword(e *core.RequestEvent) error {
	var input struct {
		Password        string `json:"password"`
		Code            string `json:"code"`
		NewPassword     string `json:"newPassword"`
		PasswordConfirm string `json:"passwordConfirm"`
	}
	if err := decode(e, &input, proofBodyBytes); err != nil {
		return err
	}
	if input.NewPassword != input.PasswordConfirm || len(input.NewPassword) < 10 || len(input.NewPassword) > 72 {
		return e.BadRequestError("Provide matching new passwords of 10 to 72 bytes.", nil)
	}
	err := runAdminOperation(e, input.Password, func(tx core.App, r *core.Record) error {
		if err := verifyAdminFactor(tx, r.Id, input.Code, false); err != nil {
			return err
		}
		r.SetPassword(input.NewPassword)
		return revokeAdminSessions(tx, r)
	})
	if err != nil {
		return err
	}
	return e.NoContent(http.StatusNoContent)
}

type adminCredentials struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

func generateAdminTOTP(e *core.RequestEvent) error {
	var input adminCredentials
	if err := decode(e, &input, proofBodyBytes); err != nil {
		return err
	}
	key := keyForTOTP(e.App)
	if len(key) != 32 {
		return e.BadRequestError("Configure a 32-byte authenticator encryption key first.", nil)
	}
	seed, err := totp.Generate(totp.GenerateOpts{Issuer: "Certimate DNS", AccountName: e.Auth.Email(), SecretSize: 20})
	if err != nil {
		return err
	}
	ciphertext, err := security.Encrypt([]byte(seed.Secret()), key)
	if err != nil {
		return err
	}
	err = runAdminOperation(e, input.Password, func(tx core.App, r *core.Record) error {
		if err := verifyAdminFactor(tx, r.Id, input.Code, false); err != nil {
			return err
		}
		_, err := tx.DB().NewQuery(`INSERT INTO dns_admin_totp_enrollment(admin,seed,fingerprint,expires)
			VALUES({:admin},{:seed},{:fingerprint},{:expires}) ON CONFLICT(admin) DO UPDATE
			SET seed=excluded.seed,fingerprint=excluded.fingerprint,expires=excluded.expires,tries=0`).
			Bind(dbx.Params{"admin": r.Id, "seed": ciphertext, "fingerprint": sessionFingerprint(r),
				"expires": time.Now().Add(5 * time.Minute).Unix()}).Execute()
		return err
	})
	if err != nil {
		return err
	}
	return e.JSON(http.StatusOK, map[string]string{"uri": seed.URL()})
}

func bindAdminTOTP(e *core.RequestEvent) error {
	var input adminCredentials
	if err := decode(e, &input, proofBodyBytes); err != nil {
		return err
	}
	err := runAdminOperation(e, input.Password, func(tx core.App, r *core.Record) error {
		var seed string
		now := time.Now()
		err := tx.DB().NewQuery(`SELECT seed FROM dns_admin_totp_enrollment
			WHERE admin={:admin} AND fingerprint={:fingerprint} AND expires>={:now} AND tries<5`).
			Bind(dbx.Params{"admin": r.Id, "fingerprint": sessionFingerprint(r), "now": now.Unix()}).Row(&seed)
		if errors.Is(err, sql.ErrNoRows) {
			return errFactor
		}
		if err != nil {
			return err
		}
		step, err := matchedStep(keyForTOTP(tx), seed, input.Code, now, 0)
		if err != nil {
			if _, err := tx.DB().NewQuery(`UPDATE dns_admin_totp_enrollment SET tries=tries+1 WHERE admin={:admin}`).
				Bind(dbx.Params{"admin": r.Id}).Execute(); err != nil {
				return err
			}
			return errFactor
		}
		_, err = tx.DB().NewQuery(`INSERT INTO dns_admin_totp(admin,seed,last_step) VALUES({:admin},{:seed},{:step})
			ON CONFLICT(admin) DO UPDATE SET seed=excluded.seed,last_step=excluded.last_step,tries=0,tries_expires=0`).
			Bind(dbx.Params{"admin": r.Id, "seed": seed, "step": step}).Execute()
		if err != nil {
			return err
		}
		return revokeAdminSessions(tx, r)
	})
	if err != nil {
		return err
	}
	return e.NoContent(http.StatusNoContent)
}

func removeAdminTOTP(e *core.RequestEvent) error {
	var input adminCredentials
	if err := decode(e, &input, proofBodyBytes); err != nil {
		return err
	}
	err := runAdminOperation(e, input.Password, func(tx core.App, r *core.Record) error {
		if err := verifyAdminFactor(tx, r.Id, input.Code, true); err != nil {
			return err
		}
		if _, err := tx.DB().Delete("dns_admin_totp", dbx.HashExp{"admin": r.Id}).Execute(); err != nil {
			return err
		}
		return revokeAdminSessions(tx, r)
	})
	if err != nil {
		return err
	}
	return e.NoContent(http.StatusNoContent)
}

func revokeAdminSessions(tx core.App, r *core.Record) error {
	if _, err := tx.DB().Delete("dns_admin_totp_enrollment", dbx.HashExp{"admin": r.Id}).Execute(); err != nil {
		return err
	}
	if err := clearAdminChallenge(tx, r.Id); err != nil {
		return err
	}
	return revokeAuthSessions(tx, r)
}

func clearAdminChallenge(app core.App, id string) error {
	_, err := app.DB().Update("dns_admin_totp", dbx.Params{"challenge": nil, "challenge_expires": 0,
		"challenge_source": nil, "fingerprint": ""}, dbx.HashExp{"admin": id}).Execute()
	return err
}
