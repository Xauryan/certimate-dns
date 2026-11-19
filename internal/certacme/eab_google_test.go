package certacme

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/go-acme/lego/v5/acme"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jws"

	"github.com/certimate-go/certimate/internal/domain"
	xcert "github.com/certimate-go/certimate/pkg/utils/cert"
)

type googleEABTestTransport func(*http.Request) (*http.Response, error)

func (f googleEABTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGoogleProjectEABRegistration(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := xcert.ConvertRSAPrivateKeyToPEM(key, true)
	if err != nil {
		t.Fatal(err)
	}
	keyJSON := `{"type":"service_account","client_email":"issuer@example.test","private_key":` + strconv.Quote(pem) + `,"token_uri":"` + google.JWTTokenURL + `"}`
	accountRepo := &googleProjectTestAccounts{records: map[[4]string]*ACMEAccount{}}
	registrations := 0
	deps := &acmeRegistrationDeps{
		accountRepo: accountRepo,
		clientFactory: func(cfg *ACMEConfig, _ *ACMEAccount) (acmeRegistrationClient, error) {
			return googleProjectTestRegistration(func(eab *eabCredential) (*acme.ExtendedAccount, error) {
				registrations++
				wantKid := "synthetic-project-eab"
				if cfg.googleEAB == nil {
					wantKid = "synthetic-manual-eab"
				}
				if eab == nil || eab.Kid != wantKid || eab.HmacKeyEncoded != "-w" {
					return nil, errors.New("registration did not receive the expected synthetic EAB binding")
				}
				return &acme.ExtendedAccount{Location: cfg.CADirUrl + "/fixture/" + cfg.googleProjectID()}, nil
			}), nil
		},
		findEABProvider: findACMEEABProvider,
	}
	for _, tc := range []struct{ name, project, mode, directory, host string }{
		{"production", "test-project-a", "live", googleLiveDirectory, "publicca.googleapis.com"},
		{"staging", "test-project-a", "staging", googleStagingDirectory, "preprod-publicca.googleapis.com"},
		{"another project", "test-project-b", "live", googleLiveDirectory, "publicca.googleapis.com"},
		{"legacy manual", "", "", googleLiveDirectory, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]any{"eabKid": "synthetic-manual-eab", "eabHmacKey": "+w=="}
			if tc.project != "" {
				values = map[string]any{"mode": tc.mode, "eabMode": "auto", "projectId": tc.project, "serviceAccountKey": keyJSON}
			}
			cfg, err := CreateACMEConfig(t.Context(), &ACMEConfigOptions{
				CAProvider: domain.CAProviderTypeGoogleTrustServices, CAProviderAccessConfig: values,
			})
			if err != nil {
				t.Fatal(err)
			}
			if cfg.CADirUrl != tc.directory || cfg.googleProjectID() != tc.project {
				t.Fatal("ACME account identity did not select the expected project and environment")
			}
			calls := 0
			if cfg.googleEAB != nil {
				cfg.googleEAB.client.Transport = googleEABTestTransport(func(req *http.Request) (*http.Response, error) {
					calls++
					if req.Method != http.MethodPost {
						t.Fatal("expected a POST")
					}
					if calls == 1 {
						if req.URL.String() != google.JWTTokenURL || req.ParseForm() != nil {
							t.Fatal("unexpected OAuth token request")
						}
						assertion := req.Form.Get("assertion")
						claims, err := jws.Decode(assertion)
						if err != nil || jws.Verify(assertion, &key.PublicKey) != nil || claims.Iss != "issuer@example.test" || claims.Aud != google.JWTTokenURL || claims.Scope != googleOAuthScope {
							t.Fatal("unexpected OAuth assertion")
						}
						return googleEABResponse(http.StatusOK, `{"access_token":"synthetic-token","token_type":"Bearer","expires_in":3600}`), nil
					}
					body, err := io.ReadAll(req.Body)
					if req.URL.String() != "https://"+tc.host+"/v1/projects/"+tc.project+"/locations/global/externalAccountKeys" || req.Header.Get("Authorization") != "Bearer synthetic-token" || err != nil || string(body) != "{}" {
						t.Fatal("unexpected Public CA EAB request")
					}
					return googleEABResponse(http.StatusOK, `{"keyId":"synthetic-project-eab","b64MacKey":"+w=="}`), nil
				})
			}
			first, err := registerACMEAccount(t.Context(), deps, cfg, "owner@example.test")
			if err != nil || first.GoogleProjectID != tc.project {
				t.Fatalf("unexpected registration result: %v", err)
			}
			second, err := registerACMEAccount(t.Context(), deps, cfg, "owner@example.test")
			if err != nil || first != second {
				t.Fatalf("same project and environment failed to reuse the registration: %v", err)
			}
			if tc.project != "" && (calls != 2 || cfg.EABKid != "" || cfg.EABHmacKey != "") {
				t.Fatal("one-time EAB key was reacquired or retained")
			}
		})
	}
	if registrations != 4 || len(accountRepo.records) != 4 {
		t.Fatal("different project, environment or manual identities were shared")
	}

	for _, badKey := range []string{
		strings.Replace(keyJSON, google.JWTTokenURL, "https://issuer.example.test/token", 1),
		strings.Replace(keyJSON, "service_account", "external_account", 1),
	} {
		if _, err := newGoogleEABProvider(domain.AccessConfigForGoogleTrustServices{ProjectID: "test-project-a", ServiceAccountKey: badKey}, googleLiveDirectory); err == nil {
			t.Fatal("unsupported OAuth credential was accepted")
		}
	}
	provider, err := newGoogleEABProvider(domain.AccessConfigForGoogleTrustServices{ProjectID: "test-project-a", ServiceAccountKey: keyJSON}, googleLiveDirectory)
	if err != nil {
		t.Fatal(err)
	}
	provider.client.Transport = googleEABTestTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != google.JWTTokenURL {
			t.Fatal("unexpected request after failed OAuth exchange")
		}
		return googleEABResponse(http.StatusForbidden, `{"error_description":"synthetic-private-response"}`), nil
	})
	_, err = provider.AcquireEAB(t.Context(), "owner@example.test")
	var failure *eabAcquireError
	if !errors.As(err, &failure) || failure.Stage != "oauth" || failure.Unwrap() != nil || strings.Contains(err.Error(), "synthetic-private-response") {
		t.Fatal("OAuth error was not sanitized")
	}
}

func googleEABResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

type googleProjectTestAccounts struct{ records map[[4]string]*ACMEAccount }

func (r *googleProjectTestAccounts) GetByCAAndEmail(_ context.Context, ca, dir, email, project string) (*ACMEAccount, error) {
	if a := r.records[[4]string{ca, dir, email, project}]; a != nil {
		return a, nil
	}
	return nil, domain.ErrRecordNotFound
}

func (r *googleProjectTestAccounts) Save(_ context.Context, a *ACMEAccount) (*ACMEAccount, error) {
	r.records[[4]string{a.CA, a.ACMEDirectoryUrl, a.Email, a.GoogleProjectID}] = a
	return a, nil
}

type googleProjectTestRegistration func(*eabCredential) (*acme.ExtendedAccount, error)

func (googleProjectTestRegistration) ExternalAccountRequired() bool { return false }

func (f googleProjectTestRegistration) Register(_ context.Context, eab *eabCredential) (*acme.ExtendedAccount, error) {
	return f(eab)
}
