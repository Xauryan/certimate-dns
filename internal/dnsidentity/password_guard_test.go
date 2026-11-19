package dnsidentity

import (
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/dbx"
)

func TestMemberCaptchaOnNativePasswordLogin(t *testing.T) {
	f := newIdentityFixture(t)
	const endpoint = "/api/collections/dns_members/auth-with-password"
	const challenge = "/api/dns-identity/captcha"
	f.call("PUT", "/api/dns-identity/member-policy", f.admin, map[string]bool{"otp": false, "mfa": false, "captcha": true}, 204)
	f.login(400)
	c := f.call("GET", challenge, "", nil, 200)
	id := value(t, c, "id")
	if c["required"] != true || !strings.HasPrefix(value(t, c, "image"), "data:image/png;base64,") {
		t.Fatal("expected a rendered image challenge")
	}
	guard := f.app.Store().Get(guardKey).(*loginGuard)
	guard.mu.Lock()
	answer := guard.challenges[id].answer
	guard.mu.Unlock()
	data := map[string]string{"identity": f.member.Email(), "password": syntheticPassword, "captchaId": id, "captcha": answer}
	f.call("POST", endpoint, "", data, 200)
	f.call("POST", endpoint, "", data, 400)
	// Only a unique successful password check clears the limit. Wrong captcha
	// input never triggers an expensive password check or consumes a reserved attempt.
	var count int
	if err := f.app.DB().NewQuery("SELECT COUNT(*) FROM dns_login_attempts").Row(&count); err != nil || count != 0 {
		t.Fatal("incorrect attempt count")
	}
}

func TestMemberPasswordLimitPersistsAcrossHookReinstall(t *testing.T) {
	f := newIdentityFixture(t)
	const endpoint = "/api/collections/dns_members/auth-with-password"
	bad := map[string]string{"identity": f.member.Email(), "password": "synthetic-incorrect"}
	f.call("POST", endpoint, "", bad, 400)
	f.login(200)
	for range 5 {
		f.call("POST", endpoint, "", bad, 400)
	}
	Install(f.app)
	f.login(429)
	if _, err := f.app.DB().NewQuery("UPDATE dns_login_attempts SET expires={:expired}").Bind(dbx.Params{"expired": time.Now().Add(-time.Second).Unix()}).Execute(); err != nil {
		t.Fatal(err)
	}
	f.login(200)
}

func TestMemberRecoveryCommand(t *testing.T) {
	f := newIdentityFixture(t)
	var output strings.Builder
	run := func(operation, input string, extra ...string) error {
		cmd := NewResetCommand(f.app)
		cmd.SetArgs(append([]string{operation, f.member.Email()}, extra...))
		cmd.SetIn(strings.NewReader(input))
		cmd.SetOut(&output)
		cmd.SetErr(&output)
		return cmd.Execute()
	}
	seed := func(active bool) {
		t.Helper()
		if _, err := f.app.DB().NewQuery("INSERT INTO dns_member_totp(member,seed,active,expires) VALUES({:member},'synthetic-test-data',{:active},0)").Bind(dbx.Params{"member": f.member.Id, "active": active}).Execute(); err != nil {
			t.Fatal(err)
		}
	}
	token := value(t, f.login(200), "token")
	seed(false)
	const newPassword = "synthetic-recovery-password"
	if err := run("pwd", "", newPassword); err == nil {
		t.Fatal("password argument unexpectedly allowed")
	}
	if err := run("pwd", "two\nlines\n"); err == nil {
		t.Fatal("multiline password unexpectedly accepted")
	}
	if err := run("pwd", newPassword+"\r\n"); err != nil {
		t.Fatal(err)
	}
	f.call("GET", "/api/dns-identity/member/totp", token, nil, 401)
	f.login(400)
	const login = "/api/collections/dns_members/auth-with-password"
	updated := map[string]string{"identity": f.member.Email(), "password": newPassword}
	token = value(t, f.call("POST", login, "", updated, 200), "token")
	seed(true)
	f.call("POST", login, "", updated, 401)
	if err := run("totp", ""); err != nil {
		t.Fatal(err)
	}
	f.call("GET", "/api/dns-identity/member/totp", token, nil, 401)
	f.call("POST", login, "", updated, 200)
	if strings.Contains(output.String(), newPassword) {
		t.Fatal("recovery command leaked password")
	}
}
