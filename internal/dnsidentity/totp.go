package dnsidentity

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/hook"
	"github.com/pocketbase/pocketbase/tools/router"
	"github.com/pocketbase/pocketbase/tools/security"
	"github.com/pquerna/otp/totp"

	"github.com/certimate-go/certimate/internal/dnsauth"
)

const totpKeyEnv = "CERTIMATE_DNS_TOTP_KEY"
const checkedTOTP = "dns.identity.totpVerified"

var errFactor = errors.New("invalid or expired authenticator verification")

func keyForTOTP(app core.App) string {
	if key := os.Getenv(totpKeyEnv); key != "" {
		return key
	}
	return os.Getenv(app.EncryptionEnv())
}

func digest(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}

func sessionFingerprint(r *core.Record) string {
	return digest(r.TokenKey() + "\x00" + r.Collection().AuthToken.Secret)
}

// Install attaches the same member policies to native PocketBase sign-in methods.
func Install(app core.App) {
	guard := newLoginGuard()
	app.Store().Set(guardKey, guard)
	app.OnRecordAuthWithPasswordRequest(dnsauth.Members).Bind(&hook.Handler[*core.RecordAuthWithPasswordRequestEvent]{
		Id: "dnsMemberPasswordChecks", Func: guard.password,
	})
	app.OnRecordAuthWithOAuth2Request(dnsauth.Members).Bind(&hook.Handler[*core.RecordAuthWithOAuth2RequestEvent]{
		Id: "dnsMemberOAuthChecks", Func: func(e *core.RecordAuthWithOAuth2RequestEvent) error {
			if e.Record == nil || e.Record.GetBool("disabled") || e.OAuth2User.Email == "" || !strings.EqualFold(e.OAuth2User.Email, e.Record.Email()) {
				return e.ForbiddenError("This identity is not enrolled for member sign-in.", nil)
			}
			if e.ProviderName == "oidc" && e.OAuth2User.RawUser["email_verified"] != true && e.OAuth2User.RawUser["email_verified"] != "true" {
				return e.ForbiddenError("The identity provider must verify the email address.", nil)
			}
			return e.Next()
		},
	})
	app.OnRecordAuthRequest(dnsauth.Members).Bind(&hook.Handler[*core.RecordAuthRequestEvent]{
		Id: "dnsMemberAuthenticator", Func: func(e *core.RecordAuthRequestEvent) error {
			// OAuth2 metadata includes the upstream access and refresh tokens.
			e.Meta = nil
			if e.AuthMethod == "" || e.Get(checkedTOTP) == e.Record.Id {
				return e.Next()
			}
			input := struct {
				MfaID string `json:"mfaId" form:"mfaId"`
			}{}
			if err := e.BindBody(&input); err != nil {
				return err
			}
			if q := e.Request.URL.Query().Get("mfaId"); q != "" {
				input.MfaID = q
			}
			if e.Collection.MFA.Enabled && e.Collection.MFA.Rule == "" && input.MfaID == "" {
				// PocketBase returns a challenge, never a session at this stage.
				return e.Next()
			}
			challenge := security.RandomString(48)
			res, err := e.App.DB().NewQuery(`UPDATE dns_member_totp SET challenge={:hash}, challenge_expires={:exp},
				session_fingerprint={:fingerprint}, auth_method={:method}, mfa_ref={:mfa}
				WHERE member={:member} AND active=1`).Bind(dbx.Params{
				"hash": digest(challenge), "exp": time.Now().Add(3 * time.Minute).Unix(), "fingerprint": sessionFingerprint(e.Record),
				"method": e.AuthMethod, "mfa": input.MfaID, "member": e.Record.Id,
			}).Execute()
			if err != nil {
				return e.InternalServerError("Could not check member authentication policy.", nil)
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			if n == 0 {
				return e.Next()
			}
			e.Response.Header().Set("Cache-Control", "no-store")
			return e.JSON(http.StatusUnauthorized, map[string]string{"totpId": challenge})
		},
	})
}

func matchedStep(key, ciphertext, code string, now time.Time, last int64) (int64, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if len(key) != 32 || err != nil || len(raw) < 28 || len(code) != 6 {
		return 0, errFactor
	}
	seed, err := security.Decrypt(ciphertext, key)
	if err != nil {
		return 0, errFactor
	}
	for _, skew := range []int64{0, -1, 1} {
		step := now.Unix()/30 + skew
		if step <= last {
			continue
		}
		expected, err := totp.GenerateCode(string(seed), time.Unix(step*30, 0))
		if err == nil && subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return step, nil
		}
	}
	return 0, errFactor
}

func rotateMember(app core.App, r *core.Record) error {
	r.RefreshTokenKey()
	if err := app.Save(r); err != nil {
		return err
	}
	for _, name := range []string{core.CollectionNameMFAs, core.CollectionNameOTPs} {
		if _, err := app.DB().Delete(name, dbx.HashExp{"collectionRef": r.Collection().Id, "recordRef": r.Id}).Execute(); err != nil {
			return err
		}
	}
	return nil
}

func bindTOTP(api *router.RouterGroup[*core.RequestEvent]) {
	member := api.Group("/dns-identity/member").Bind(apis.RequireAuth(dnsauth.Members), apis.BodyLimit(4096))
	member.GET("/totp", func(e *core.RequestEvent) error {
		var active bool
		err := e.App.DB().NewQuery(`SELECT EXISTS (SELECT 1 FROM dns_member_totp WHERE member={:id} AND active=1)`).Bind(dbx.Params{"id": e.Auth.Id}).Row(&active)
		if err != nil {
			return err
		}
		return e.JSON(200, map[string]bool{"active": active, "available": len(keyForTOTP(e.App)) == 32})
	})
	member.POST("/totp/generate", func(e *core.RequestEvent) error {
		var input struct {
			Password string `json:"password"`
		}
		if err := decode(e, &input); err != nil {
			return err
		}
		if !e.Auth.ValidatePassword(input.Password) {
			return e.BadRequestError("Invalid current password.", nil)
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
		res, err := e.App.DB().NewQuery(`INSERT INTO dns_member_totp(member,seed,expires) VALUES({:member},{:seed},{:exp})
			ON CONFLICT(member) DO UPDATE SET seed=excluded.seed,expires=excluded.expires,tries=0 WHERE active=0`).Bind(dbx.Params{
			"member": e.Auth.Id, "seed": ciphertext, "exp": time.Now().Add(5 * time.Minute).Unix(),
		}).Execute()
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return e.BadRequestError("An authenticator is already enrolled.", nil)
		}
		e.Response.Header().Set("Cache-Control", "no-store")
		return e.JSON(200, map[string]string{"uri": seed.URL()})
	})
	for _, op := range []string{"bind", "remove"} {
		member.POST("/totp/"+op, func(e *core.RequestEvent) error {
			var input struct {
				Password string `json:"password"`
				Code     string `json:"code"`
			}
			if err := decode(e, &input); err != nil {
				return err
			}
			if !e.Auth.ValidatePassword(input.Password) {
				return e.BadRequestError("Invalid current password.", nil)
			}
			err := e.App.RunInTransaction(func(tx core.App) error {
				r, err := tx.FindRecordById(dnsauth.Members, e.Auth.Id)
				if err != nil || r.GetBool("disabled") || r.TokenKey() != e.Auth.TokenKey() {
					return errFactor
				}
				var seed string
				var last, expires int64
				err = tx.DB().NewQuery(`SELECT seed,last_step,expires FROM dns_member_totp WHERE member={:member} AND active={:active}`).Bind(dbx.Params{"member": r.Id, "active": op == "remove"}).Row(&seed, &last, &expires)
				if err != nil || op == "bind" && expires < time.Now().Unix() {
					return errFactor
				}
				step, err := matchedStep(keyForTOTP(tx), seed, input.Code, time.Now(), last)
				if err != nil {
					return err
				}
				if op == "remove" {
					_, err = tx.DB().Delete("dns_member_totp", dbx.HashExp{"member": r.Id}).Execute()
				} else {
					_, err = tx.DB().Update("dns_member_totp", dbx.Params{"active": true, "expires": 0, "last_step": step}, dbx.HashExp{"member": r.Id}).Execute()
				}
				if err != nil {
					return err
				}
				return rotateMember(tx, r)
			})
			if err != nil {
				return e.BadRequestError("Authenticator verification failed.", nil)
			}
			return e.NoContent(204)
		})
	}
	api.POST("/dns-identity/totp/login", verifyLogin).Bind(apis.BodyLimit(4096))
}

func verifyLogin(e *core.RequestEvent) error {
	var input struct {
		ID   string `json:"totpId"`
		Code string `json:"code"`
	}
	if err := e.BindBody(&input); err != nil || len(input.ID) != 48 {
		return e.BadRequestError("Invalid challenge.", nil)
	}
	var record *core.Record
	var method, mfa string
	err := e.App.RunInTransaction(func(tx core.App) error {
		var seed, member, fingerprint string
		var last int64
		hash := digest(input.ID)
		err := tx.DB().NewQuery(`SELECT seed,member,session_fingerprint,auth_method,mfa_ref,last_step FROM dns_member_totp
			WHERE active=1 AND challenge={:hash} AND challenge_expires>={:now} AND (tries<5 OR tries_expire<={:now})`).Bind(dbx.Params{"hash": hash, "now": time.Now().Unix()}).Row(&seed, &member, &fingerprint, &method, &mfa, &last)
		if err != nil {
			return err
		}
		r, err := tx.FindRecordById(dnsauth.Members, member)
		if err != nil || r.GetBool("disabled") || sessionFingerprint(r) != fingerprint {
			return errFactor
		}
		step, err := matchedStep(keyForTOTP(tx), seed, input.Code, time.Now(), last)
		if err != nil {
			_, err = tx.DB().NewQuery(`UPDATE dns_member_totp SET tries=CASE WHEN tries_expire<={:now} THEN 1 ELSE tries+1 END,
 tries_expire=CASE WHEN tries_expire<={:now} THEN {:expiry} ELSE tries_expire END WHERE challenge={:hash}`).Bind(dbx.Params{"hash": hash, "now": time.Now().Unix(), "expiry": time.Now().Add(10 * time.Minute).Unix()}).Execute()
			return err // commit the failed attempt
		}
		_, err = tx.DB().Update("dns_member_totp", dbx.Params{"challenge": nil, "last_step": step, "tries": 0, "tries_expire": 0}, dbx.HashExp{"challenge": hash}).Execute()
		if err == nil {
			record = r
		}
		return err
	})
	if err != nil && !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, errFactor) {
		return e.InternalServerError("Could not check challenge.", nil)
	}
	if record == nil || err != nil {
		return e.BadRequestError("Invalid or expired authenticator challenge.", nil)
	}
	q := e.Request.URL.Query()
	q.Set("mfaId", mfa)
	e.Request.URL.RawQuery = q.Encode()
	e.Set(checkedTOTP, record.Id)
	return apis.RecordAuthResponse(e, record, method, nil)
}
