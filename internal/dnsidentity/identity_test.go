package dnsidentity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pquerna/otp/totp"

	"github.com/certimate-go/certimate/internal/dnsauth"
	_ "github.com/certimate-go/certimate/migrations"
)

const syntheticPassword = "member-test-password"

type identityFixture struct {
	t       *testing.T
	app     *core.BaseApp
	handler http.Handler
	admin   string
	member  *core.Record
}

func newIdentityFixture(t *testing.T) *identityFixture {
	t.Helper()
	t.Setenv(totpKeyEnv, "0123456789ABCDEF0123456789ABCDEF")
	t.Setenv("CERTIMATE_ADMIN_USERNAME", "root@example.test")
	t.Setenv("CERTIMATE_ADMIN_PASSWORD", "synthetic-admin-password")
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.ResetBootstrapState() })
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	c, err := app.FindCollectionByNameOrId(dnsauth.Members)
	if err != nil {
		t.Fatal(err)
	}
	r := core.NewRecord(c)
	r.SetEmail("member@example.test")
	r.SetPassword(syntheticPassword)
	if err := app.Save(r); err != nil {
		t.Fatal(err)
	}
	a, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "root@example.test")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := a.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	Install(app)
	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	Bind(router.Group("/api"))
	BindWebhook(router.Group("/api"))
	mux, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	return &identityFixture{t: t, app: app, handler: mux, member: r, admin: admin}
}

func (f *identityFixture) call(method, path, token string, body any, want int) map[string]any {
	f.t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		f.t.Fatal(err)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", token)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != want {
		f.t.Fatalf("%s %s got %d want %d", method, path, w.Code, want)
	}
	result := map[string]any{}
	if w.Body.Len() != 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			f.t.Fatal(err)
		}
	}
	return result
}

func (f *identityFixture) login(status int) map[string]any {
	return f.call("POST", "/api/collections/dns_members/auth-with-password", "", map[string]string{"identity": f.member.Email(), "password": syntheticPassword}, status)
}
func value(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	s, ok := m[key].(string)
	if !ok || s == "" {
		t.Fatalf("missing %s in response", key)
	}
	return s
}

func TestAuthenticatorEnrollmentRevokesSessionsAndProtectsNativeLogin(t *testing.T) {
	f := newIdentityFixture(t)
	token := value(t, f.login(200), "token")
	const path = "/api/dns-identity/member/totp"
	f.call("GET", path, "", nil, 401)
	got := f.call("POST", path+"/generate", token, map[string]string{"password": syntheticPassword}, 200)
	uri, err := url.Parse(value(t, got, "uri"))
	if err != nil {
		t.Fatal(err)
	}
	secret := uri.Query().Get("secret")
	var saved string
	if err := f.app.DB().NewQuery("SELECT seed FROM dns_member_totp").Row(&saved); err != nil || saved == "" || strings.Contains(saved, secret) {
		t.Fatal("authenticator seed not encrypted")
	}
	now := time.Now()
	prevCode, err := totp.GenerateCode(secret, now.Add(-30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	f.call("POST", path+"/bind", token, map[string]string{"password": syntheticPassword, "code": prevCode}, 204)
	f.call("GET", path, token, nil, 401)
	login := f.login(401)
	if _, ok := login["token"]; ok {
		t.Fatal("session issued before proof")
	}
	challenge := value(t, login, "totpId")
	const verify = "/api/dns-identity/totp/login"
	f.call("POST", verify, "", map[string]string{"totpId": challenge, "code": "invalid"}, 400)
	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	newToken := value(t, f.call("POST", verify, "", map[string]string{"totpId": challenge, "code": code}, 200), "token")
	f.call("POST", verify, "", map[string]string{"totpId": challenge, "code": code}, 400)
	second := value(t, f.login(401), "totpId")
	f.call("POST", verify, "", map[string]string{"totpId": second, "code": code}, 400)
	future, err := totp.GenerateCode(secret, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	f.call("POST", path+"/remove", newToken, map[string]string{"password": syntheticPassword, "code": future}, 204)
	f.call("GET", path, newToken, nil, 401)
	f.login(200)
}

func TestMemberPolicyOIDCAndMFA(t *testing.T) {
	f := newIdentityFixture(t)
	user := value(t, f.login(200), "token")
	const policy = "/api/dns-identity/member-policy"
	const oidc = "/api/dns-identity/oidc"
	f.call("GET", policy, user, nil, 403)
	f.call("PUT", policy, f.admin, map[string]bool{"mfa": true, "otp": false}, 400)
	s := map[string]any{"enabled": true, "displayName": "Synthetic IDP", "authUrl": "https://idp.example.test/auth", "tokenUrl": "https://idp.example.test/token", "userInfoUrl": "https://idp.example.test/user", "clientId": "sample", "clientSecret": "synthetic-client-secret"}
	f.call("PUT", oidc, f.admin, s, 204)
	cfg := f.call("GET", oidc, f.admin, nil, 200)
	if _, ok := cfg["clientSecret"]; ok {
		t.Fatal("client secret disclosed")
	}
	f.call("GET", "/api/dns-identity/member/totp", user, nil, 401)
	s["clientSecret"] = ""
	s["authUrl"] = "https://other.example.test/auth"
	f.call("PUT", oidc, f.admin, s, 400)
	f.call("PUT", policy, f.admin, map[string]bool{"mfa": true, "otp": true}, 204)
	first := f.login(401)
	id := value(t, first, "mfaId")
	const login = "/api/collections/dns_members/auth-with-password?mfaId="
	f.call("POST", login+id, "", map[string]string{"identity": f.member.Email(), "password": syntheticPassword}, 400)
	otp := core.NewOTP(f.app)
	otp.SetRecordRef(f.member.Id)
	otp.SetCollectionRef(f.member.Collection().Id)
	otp.SetPassword("12345678")
	if err := f.app.Save(otp); err != nil {
		t.Fatal(err)
	}
	value(t, f.call("POST", "/api/collections/dns_members/auth-with-otp?mfaId="+id, "", map[string]string{"otpId": otp.Id, "password": "12345678"}, 200), "token")
}

func TestQQSignedBindingAndDestinationIsolation(t *testing.T) {
	f := newIdentityFixture(t)
	const secret = "synthetic-bot-secret"
	t.Setenv(secretEnv, secret)
	const qq = "/api/dns-identity/qq"
	f.call("PUT", qq, f.admin, map[string]any{"enabled": true, "appId": "1234", "openId": ""}, 204)
	code := value(t, f.call("POST", qq+"/bind", f.admin, nil, 200), "code")
	now := strconv.FormatInt(time.Now().Unix(), 10)
	seed := strings.Repeat(secret, 1+(ed25519.SeedSize-1)/len(secret))[:ed25519.SeedSize]
	key := ed25519.NewKeyFromSeed([]byte(seed))
	send := func(openID, content, stamp string, signed bool, expected int) {
		t.Helper()
		data := map[string]any{"op": 0, "t": "C2C_MESSAGE_CREATE", "d": map[string]any{"content": content, "author": map[string]string{"user_openid": openID}}}
		b, _ := json.Marshal(data)
		r := httptest.NewRequest("POST", qq+"/webhook", bytes.NewReader(b))
		r.Header.Set("X-Bot-Appid", "1234")
		r.Header.Set("X-Signature-Timestamp", stamp)
		if signed {
			r.Header.Set("X-Signature-Ed25519", hex.EncodeToString(ed25519.Sign(key, append([]byte(stamp), b...))))
		}
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		if w.Code != expected {
			t.Fatalf("callback HTTP %d want %d", w.Code, expected)
		}
	}
	send("first", code, now, false, 401)
	send("first", code, "100", true, 401)
	send("first", code, now, true, 200)
	send("second", code, now, true, 200)
	got := f.call("GET", qq, f.admin, nil, 200)
	if got["openId"] != "first" || got["confirmedAt"] == float64(0) {
		t.Fatal("signed binding did not preserve the accepted recipient")
	}
}

type qqRoundTrip func(*http.Request) (*http.Response, error)

func (rt qqRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return rt(r) }

func TestQQTransportCredentialsAndReceipt(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: qqRoundTrip(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Scheme != "https" || req.URL.Host != "api.bot.qq.com" {
			t.Fatal("unexpected QQ API host")
		}
		response := ""
		switch calls {
		case 1:
			if req.URL.Path != "/app/getAppAccessToken" {
				t.Fatal("incorrect QQ token endpoint")
			}
			response = `{"access_token":"synthetic-token"}`
		case 2:
			if req.URL.Path != "/v2/users/abc/messages" || req.Header.Get("Authorization") != "QQBot synthetic-token" {
				t.Fatal("incorrect QQ recipient or bot authorization")
			}
			response = `{"id":"message"}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(response)), Header: http.Header{}}, nil
	})}
	if err := sendQQ(context.Background(), destination{Enabled: true, AppID: "123", OpenID: "abc"}, "synthetic-secret", "test", client); err != nil || calls != 2 {
		t.Fatal("synthetic transport delivery failed")
	}
}

func TestQQAutomationDistinguishesDisabledAndMissingRecipient(t *testing.T) {
	f := newIdentityFixture(t)
	t.Setenv(secretEnv, "synthetic-bot-secret")
	ok, err := NotifyQQ(context.Background(), f.app, "task", "run", "create", "ok")
	if ok || err != nil {
		t.Fatal("disabled transport reported a delivery or failure")
	}
	f.call("PUT", "/api/dns-identity/qq", f.admin, map[string]any{"enabled": true, "appId": "123", "openId": ""}, 204)
	ok, err = NotifyQQ(context.Background(), f.app, "task", "run", "create", "ok")
	if ok || err == nil {
		t.Fatal("incomplete destination reported successful delivery")
	}
}

func TestOIDCLoginRequiresVerifiedEnrolledIdentity(t *testing.T) {
	f := newIdentityFixture(t)
	// Install a loopback test identity provider directly on the fixture collection.
	// The production settings endpoint restricts administrators to HTTPS endpoints.
	var email atomic.Value
	email.Store(f.member.Email())
	var verified atomic.Bool
	verified.Store(true)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			io.WriteString(w, `{"access_token":"synthetic-token","refresh_token":"synthetic-refresh","token_type":"Bearer"}`)
		case "/user":
			if r.Header.Get("Authorization") != "Bearer synthetic-token" {
				w.WriteHeader(401)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"sub": "test-subject", "email": email.Load(), "email_verified": verified.Load()})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(provider.Close)
	c, err := f.app.FindCollectionByNameOrId(dnsauth.Members)
	if err != nil {
		t.Fatal(err)
	}
	c.OAuth2.Enabled = true
	c.OAuth2.Providers = []core.OAuth2ProviderConfig{{Name: "oidc", ClientId: "synthetic-client", ClientSecret: "synthetic-secret", AuthURL: provider.URL + "/auth", TokenURL: provider.URL + "/token", UserInfoURL: provider.URL + "/user"}}
	if err = f.app.Save(c); err != nil {
		t.Fatal(err)
	}
	login := func(status int) map[string]any {
		return f.call("POST", "/api/collections/dns_members/auth-with-oauth2", "", map[string]string{"provider": "oidc", "code": "synthetic", "codeVerifier": strings.Repeat("a", 43), "redirectURL": "https://app.example.test/api/oauth2-redirect"}, status)
	}
	verified.Store(false)
	login(403)
	verified.Store(true)
	email.Store("stranger@example.test")
	login(403)
	email.Store(f.member.Email())
	data := login(200)
	value(t, data, "token")
	if data["meta"] != nil {
		t.Fatal("OAuth provider metadata disclosed to browser")
	}
	f.member, err = f.app.FindRecordById(dnsauth.Members, f.member.Id)
	if err != nil {
		t.Fatal(err)
	}
	f.member.Set("disabled", true)
	if err = f.app.Save(f.member); err != nil {
		t.Fatal(err)
	}
	login(403)
}
