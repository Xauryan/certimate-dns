package dnsidentity

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pquerna/otp/totp"
)

const (
	adminEmail       = "root@example.test"
	adminPassword    = "synthetic-admin-password"
	adminNativeLogin = "/api/collections/_superusers/auth-with-password"
	adminIdentityAPI = "/api/dns-identity/admin"
)

func adminLogin(f *identityFixture, password string, status int) map[string]any {
	f.t.Helper()
	return f.call("POST", adminNativeLogin, "", map[string]string{"identity": adminEmail, "password": password}, status)
}

func adminAccount(f *identityFixture) *core.Record {
	f.t.Helper()
	r, err := f.app.FindAuthRecordByEmail(core.CollectionNameSuperusers, adminEmail)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func adminSeed(f *identityFixture, token, currentCode string) string {
	f.t.Helper()
	result := f.call("POST", adminIdentityAPI+"/totp/generate", token, map[string]string{"password": adminPassword, "code": currentCode}, 200)
	uri, err := url.Parse(value(f.t, result, "uri"))
	if err != nil {
		f.t.Fatal(err)
	}
	secret := uri.Query().Get("secret")
	var saved string
	err = f.app.DB().NewQuery("SELECT seed FROM dns_admin_totp_enrollment").Row(&saved)
	if err != nil || saved == "" || strings.Contains(saved, secret) {
		f.t.Fatal("authenticator seed was not encrypted")
	}
	return secret
}

func adminCode(t *testing.T, seed string, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCode(seed, at)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func completeAdminLogin(f *identityFixture, challenge, code string, status int) map[string]any {
	f.t.Helper()
	return f.call("POST", adminIdentityAPI+"/totp/login", "", map[string]string{"totpId": challenge, "code": code}, status)
}

func assertAdminChallenge(t *testing.T, response map[string]any) string {
	t.Helper()
	if len(response) != 1 {
		t.Fatal("authenticator challenge exposed native authorization data")
	}
	return value(t, response, "totpId")
}

func TestAdministratorCaptchaAndPersistentLoginLimit(t *testing.T) {
	f := newIdentityFixture(t)
	const captchaPath = adminIdentityAPI + "/captcha"
	const policyPath = adminIdentityAPI + "/policy"
	normal := adminLogin(f, adminPassword, 200)
	token := value(t, normal, "token")
	if f.call("GET", captchaPath, "", nil, 200)["required"] != false {
		t.Fatal("default login unexpectedly requires an image code")
	}
	f.call("PUT", policyPath, token, map[string]any{"captcha": true, "password": "incorrect"}, 400)
	memberToken := value(t, f.login(200), "token")
	f.call("PUT", policyPath, memberToken, map[string]any{"captcha": true, "password": syntheticPassword}, 403)
	f.call("PUT", policyPath, token, map[string]any{"captcha": true, "password": adminPassword}, 204)
	adminLogin(f, adminPassword, 400)
	f.login(200)

	data := func(pw string) map[string]string {
		c := f.call("GET", captchaPath, "", nil, 200)
		id := value(t, c, "id")
		if c["required"] != true || !strings.HasPrefix(value(t, c, "image"), "data:image/png;base64,") {
			t.Fatal("expected a rendered image challenge")
		}
		guard := f.app.Store().Get(adminGuardKey).(*loginGuard)
		guard.mu.Lock()
		defer guard.mu.Unlock()
		return map[string]string{"identity": adminEmail, "password": pw, "captchaId": id, "captcha": guard.challenges[id].answer}
	}
	correct := data(adminPassword)
	f.call("POST", adminNativeLogin, "", correct, 200)
	f.call("POST", adminNativeLogin, "", correct, 400)
	for range 5 {
		f.call("POST", adminNativeLogin, "", data("synthetic-incorrect"), 400)
	}
	Install(f.app)
	f.call("POST", adminNativeLogin, "", data(adminPassword), 429)
	f.login(200)
	unlock := NewAdminResetCommand(f.app)
	unlock.SetArgs([]string{"unlock"})
	if err := unlock.Execute(); err != nil {
		t.Fatal(err)
	}
	f.call("POST", adminNativeLogin, "", data(adminPassword), 200)
}

func TestAdministratorNativeAuthenticationAndRecovery(t *testing.T) {
	f := newIdentityFixture(t)
	const appPath = adminIdentityAPI + "/security"
	const factorPath = adminIdentityAPI + "/totp"
	const native = "/api/collections/_superusers"
	var cliOutput strings.Builder
	recover := func(method, input string) {
		t.Helper()
		cmd := NewAdminResetCommand(f.app)
		cmd.SetArgs([]string{method, adminEmail})
		cmd.SetIn(strings.NewReader(input))
		cmd.SetOut(&cliOutput)
		cmd.SetErr(&cliOutput)
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
	}

	initial := value(t, adminLogin(f, adminPassword, 200), "token")
	f.call("GET", appPath, "", nil, 401)
	f.call("POST", factorPath+"/generate", value(t, f.login(200), "token"), map[string]string{"password": adminPassword}, 403)
	secret := adminSeed(f, initial, "")
	bindTime := time.Now().Add(-30 * time.Second)
	f.call("POST", factorPath+"/bind", initial, map[string]string{"password": adminPassword, "code": adminCode(t, secret, bindTime)}, 204)
	f.call("GET", appPath, initial, nil, 401)
	login := assertAdminChallenge(t, adminLogin(f, adminPassword, 401))
	completeAdminLogin(f, login, "invalid", 400)
	now := time.Now()
	code := adminCode(t, secret, now)
	token := value(t, completeAdminLogin(f, login, code, 200), "token")
	completeAdminLogin(f, login, code, 400)
	if f.call("GET", appPath, token, nil, 200)["active"] != true {
		t.Fatal("authenticator was not active after enrollment")
	}
	f.call("POST", native+"/auth-refresh", token, nil, 200)
	route := native + "/records/" + adminAccount(f).Id
	f.call("POST", native+"/impersonate/"+adminAccount(f).Id, token, map[string]int{"duration": 60}, 403)
	f.call("PATCH", route, token, map[string]string{"password": "synthetic-other-password", "passwordConfirm": "synthetic-other-password"}, 403)
	challenge := assertAdminChallenge(t, adminLogin(f, adminPassword, 401))
	completeAdminLogin(f, challenge, code, 400)
	f.call("POST", factorPath+"/generate", token, map[string]string{"password": adminPassword, "code": "invalid"}, 400)
	f.call("POST", factorPath+"/remove", token, map[string]string{"password": adminPassword, "code": "invalid"}, 400)
	f.call("PUT", adminIdentityAPI+"/policy", token, map[string]any{"captcha": true, "password": adminPassword, "code": "invalid"}, 400)

	// Starting a replacement keeps the original authenticator active until proof
	// of the new authenticator is accepted.
	replacement := adminSeed(f, token, adminCode(t, secret, time.Now().Add(30*time.Second)))
	f.call("POST", factorPath+"/bind", token, map[string]string{"password": adminPassword, "code": "invalid"}, 400)
	if f.call("GET", appPath, token, nil, 200)["active"] != true {
		t.Fatal("replacement switched the authenticator before proof")
	}
	f.call("POST", factorPath+"/bind", token, map[string]string{"password": adminPassword, "code": adminCode(t, replacement, time.Now().Add(-30*time.Second))}, 204)
	f.call("GET", appPath, token, nil, 401)
	completeAdminLogin(f, challenge, adminCode(t, replacement, time.Now()), 400)
	challenge = assertAdminChallenge(t, adminLogin(f, adminPassword, 401))
	token = value(t, completeAdminLogin(f, challenge, adminCode(t, replacement, time.Now()), 200), "token")

	const changed = "synthetic-admin-changed-password"
	change := map[string]string{"password": adminPassword, "newPassword": changed, "passwordConfirm": changed, "code": "invalid"}
	f.call("POST", adminIdentityAPI+"/password", token, change, 400)
	change["code"] = adminCode(t, replacement, time.Now().Add(30*time.Second))
	f.call("POST", adminIdentityAPI+"/password", token, change, 204)
	f.call("GET", appPath, token, nil, 401)
	adminLogin(f, adminPassword, 400)
	assertAdminChallenge(t, adminLogin(f, changed, 401))

	const recovered = "synthetic-admin-recovered-password"
	recover("password", recovered+"\r\n")
	adminLogin(f, changed, 400)
	pending := assertAdminChallenge(t, adminLogin(f, recovered, 401))
	recover("totp", "")
	completeAdminLogin(f, pending, adminCode(t, replacement, time.Now()), 400)
	adminLogin(f, recovered, 200)
	if strings.Contains(cliOutput.String(), recovered) {
		t.Fatal("CLI recovery disclosed the new password")
	}
}

func TestAdministratorTOTPAfterNativeEmailMFA(t *testing.T) {
	f := newIdentityFixture(t)
	secret := adminSeed(f, f.admin, "")
	f.call("POST", adminIdentityAPI+"/totp/bind", f.admin, map[string]string{
		"password": adminPassword, "code": adminCode(t, secret, time.Now().Add(-30*time.Second)),
	}, 204)
	r := adminAccount(f)
	r.SetVerified(true)
	if err := f.app.Save(r); err != nil {
		t.Fatal(err)
	}
	c := r.Collection()
	c.OTP.Enabled, c.MFA.Enabled = true, true
	if err := f.app.Save(c); err != nil {
		t.Fatal(err)
	}
	mfa := adminLogin(f, adminPassword, 401)
	id := value(t, mfa, "mfaId")
	if len(mfa) != 1 {
		t.Fatal("PocketBase MFA did not run before the authenticator step")
	}
	otp := core.NewOTP(f.app)
	otp.SetCollectionRef(c.Id)
	otp.SetRecordRef(r.Id)
	otp.SetSentTo(r.Email())
	otp.SetPassword("392058")
	if err := f.app.Save(otp); err != nil {
		t.Fatal(err)
	}
	prove := map[string]string{"otpId": otp.Id, "password": "392058"}
	response := f.call("POST", "/api/collections/"+c.Id+"/auth-with-otp?mfaId="+id, "", prove, 401)
	challenge := assertAdminChallenge(t, response)
	for range adminFactorAttempts {
		completeAdminLogin(f, challenge, "wrong", 400)
	}
	code := adminCode(t, secret, time.Now())
	completeAdminLogin(f, challenge, code, 400)
	if _, err := f.app.DB().Update("dns_admin_totp", dbx.Params{"tries_expires": 0}, dbx.HashExp{"admin": r.Id}).Execute(); err != nil {
		t.Fatal(err)
	}
	token := value(t, completeAdminLogin(f, challenge, code, 200), "token")
	f.call("POST", adminIdentityAPI+"/totp/remove", token, map[string]string{
		"password": adminPassword, "code": adminCode(t, secret, time.Now().Add(30*time.Second)),
	}, 204)
	f.call("GET", adminIdentityAPI+"/security", token, nil, 401)
	value(t, adminLogin(f, adminPassword, 401), "mfaId")
}
