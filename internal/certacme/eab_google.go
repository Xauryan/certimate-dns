package certacme

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"

	"github.com/certimate-go/certimate/internal/domain"
	xcert "github.com/certimate-go/certimate/pkg/utils/cert"
)

const (
	googleLiveDirectory    = "https://dv.acme-v02.api.pki.goog/directory"
	googleStagingDirectory = "https://dv.acme-v02.test-api.pki.goog/directory"
	googleEABProviderID    = "googletrustservices"
	googleOAuthScope       = "https://www.googleapis.com/auth/cloud-platform"
)

var googleProjectIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)

type googleEABProvider struct {
	projectID string
	endpoint  string
	jwt       *jwt.Config
	client    *http.Client
}

func (c *ACMEConfig) googleProjectID() string {
	if c.googleEAB == nil {
		return ""
	}
	return c.googleEAB.projectID
}

func newGoogleEABProvider(config domain.AccessConfigForGoogleTrustServices, directory string) (*googleEABProvider, error) {
	if !googleProjectIDPattern.MatchString(config.ProjectID) {
		return nil, errors.New("invalid Google Cloud project ID")
	}
	signer, err := google.JWTConfigFromJSON([]byte(config.ServiceAccountKey), googleOAuthScope)
	if err != nil || signer.Email == "" || signer.TokenURL != google.JWTTokenURL || signer.Audience != "" && signer.Audience != google.JWTTokenURL {
		return nil, errors.New("Google Public CA requires a Google service account key with the official OAuth token endpoint")
	}
	key, err := xcert.ParsePrivateKeyFromPEM(string(signer.PrivateKey))
	if _, ok := key.(*rsa.PrivateKey); err != nil || !ok {
		return nil, errors.New("invalid Google service account private key")
	}
	host := "https://publicca.googleapis.com"
	if directory == googleStagingDirectory {
		host = "https://preprod-publicca.googleapis.com"
	}
	return &googleEABProvider{
		projectID: config.ProjectID,
		endpoint:  host + "/v1/projects/" + config.ProjectID + "/locations/global/externalAccountKeys",
		jwt:       signer,
		client:    newEABHTTPClient(),
	}, nil
}

// Google EABs are consumed by registration. Only the resulting ACME account is reusable.
func (*googleEABProvider) Reusable() bool { return false }

func (p *googleEABProvider) AcquireEAB(ctx context.Context, _ string) (*eabCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, eabAcquireRequestTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.client)
	token, err := p.jwt.TokenSource(ctx).Token()
	if err != nil || !token.Valid() {
		// OAuth errors can include the token server's raw response.
		return nil, &eabAcquireError{Stage: "oauth", ProviderId: googleEABProviderID}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, strings.NewReader("{}"))
	if err != nil {
		return nil, &eabAcquireError{Stage: eabAcquireStageRequest, ProviderId: googleEABProviderID}
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		problem := classifyEABTransportError(googleEABProviderID, err)
		problem.cause = nil
		return nil, problem
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &eabAcquireError{Stage: eabAcquireStageHTTPStatus, ProviderId: googleEABProviderID, HTTPStatus: resp.StatusCode}
	}
	data, err := readEABResponseBody(resp.Body)
	var key struct {
		KeyID string `json:"keyId"`
		MAC   string `json:"b64MacKey"`
	}
	if err != nil || json.Unmarshal(data, &key) != nil {
		return nil, &eabAcquireError{Stage: eabAcquireStageResponse, ProviderId: googleEABProviderID}
	}
	key.KeyID = strings.TrimSpace(key.KeyID)
	mac := normalizeEABHmacKeyEncoded(key.MAC)
	raw, err := base64.RawURLEncoding.DecodeString(mac)
	if key.KeyID == "" || err != nil || len(raw) == 0 {
		return nil, &eabAcquireError{Stage: eabAcquireStageCredentials, ProviderId: googleEABProviderID}
	}
	return &eabCredential{Kid: key.KeyID, HmacKeyEncoded: mac}, nil
}
