// Package dnscert manages commercial CA orders using existing Certimate access
// records. Only explicit administrator actions contact an issuer.
package dnscert

import (
	"context"
	"errors"
	"net"
	"net/mail"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/certimate-go/certimate/internal/domain"
	"golang.org/x/net/idna"
)

var (
	errProvider     = errors.New("certificate provider request failed")
	errInput        = errors.New("invalid certificate order input")
	errConflict     = errors.New("certificate order changed or is awaiting reconciliation")
	errMissing      = errors.New("certificate order or account not found")
	remoteIDPattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9.:-]{0,254}$")
	hostLabel       = regexp.MustCompile("^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
)

type OrderRequest struct {
	Domain       string `json:"domain"`
	SourceZoneID string `json:"sourceZoneId,omitempty"`
	Algorithm    string `json:"algorithm"`
	Email        string `json:"email,omitempty"`
	ContactName  string `json:"contactName,omitempty"`
	Phone        string `json:"phone,omitempty"`
	Organization string `json:"organization,omitempty"`
	Address      string `json:"address,omitempty"`
	City         string `json:"city,omitempty"`
	Province     string `json:"province,omitempty"`
	Country      string `json:"country,omitempty"`
	PostalCode   string `json:"postalCode,omitempty"`
	Department   string `json:"department,omitempty"`
	Title        string `json:"title,omitempty"`
	InstanceID   string `json:"instanceId,omitempty"`
	ContactID    string `json:"contactId,omitempty"`
}
type Challenge struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}
type Snapshot struct {
	Domain     string
	State      string
	Challenges []Challenge
}
type Material struct {
	Certificate string `json:"-"`
	PrivateKey  string `json:"-"`
}
type Issuer interface {
	Check(ctx context.Context) error
	Create(ctx context.Context, req OrderRequest) (string, error)
	Submit(ctx context.Context, id string, req OrderRequest) error
	Inspect(ctx context.Context, id string) (Snapshot, error)
	Verify(ctx context.Context, id string) error
	Download(ctx context.Context, id string) (Material, error)
	Cancel(ctx context.Context, id string) error
	Revoke(ctx context.Context, id string) ([]Challenge, error)
}
type accessReader interface {
	GetById(context.Context, string) (*domain.Access, error)
}
type factory func(*domain.Access) (Issuer, error)

func newIssuer(a *domain.Access) (Issuer, error) {
	switch a.Provider {
	case "aliyun":
		return newAliyun(a)
	case "tencentcloud":
		return newTencent(a)
	case "ucloud":
		return newUCloud(a)
	default:
		return nil, errInput
	}
}

// CheckCredential validates a proposed administrator credential before it is saved.
func CheckCredential(ctx context.Context, a *domain.Access) error {
	if a == nil || a.DeletedAt != nil || a.Reserve != "" && a.Reserve != "ca" {
		return errInput
	}
	issuer, err := newIssuer(a)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return issuer.Check(ctx)
}

func field(a *domain.Access, key string) string {
	v, _ := a.Config[key].(string)
	return v
}

type Order struct {
	ID             string      `json:"id" db:"id"`
	PrimaryZoneID  string      `json:"sourceZoneId,omitempty" db:"primary_zone_id"`
	ReplacementID  string      `json:"replacementId,omitempty" db:"replacement_id"`
	AccessID       string      `json:"accessId" db:"access_id"`
	Provider       string      `json:"provider" db:"provider"`
	Domain         string      `json:"domain" db:"domain"`
	Algorithm      string      `json:"algorithm" db:"algorithm"`
	State          string      `json:"state" db:"state"`
	RemoteID       string      `json:"remoteId,omitempty" db:"remote_id"`
	CertificateID  string      `json:"certificateId,omitempty" db:"certificate_id"`
	Version        int         `json:"version" db:"version"`
	Challenges     []Challenge `json:"challenges" db:"-"`
	AllowedActions []string    `json:"allowedActions" db:"-"`
	RequestJSON    string      `json:"-" db:"request_json"`
	ChallengesJSON string      `json:"-" db:"challenges_json"`
	LeaseEnd       int64       `json:"-" db:"lease_end"`
	Created        int64       `json:"created" db:"created"`
	Updated        int64       `json:"updated" db:"updated"`
}

func (o Order) actions(now time.Time) []string {
	actions := []string{}
	if o.LeaseEnd > now.Unix() {
		return actions
	}
	switch o.State {
	case "draft":
		return []string{"edit", "create", "cancel", "delete"}
	case "creating":
		return []string{"recover"}
	case "reserved":
		actions = append(actions, "submit", "refresh", "cancel")
	case "submitting":
		actions = append(actions, "refresh")
	case "pending":
		actions = append(actions, "refresh", "verify", "cancel")
	case "issued":
		actions = append(actions, "refresh")
		if o.CertificateID == "" {
			actions = append(actions, "download")
		}
		actions = append(actions, "revoke")
	case "failed", "cancelled", "expired", "revoked":
		if o.ReplacementID == "" {
			actions = append(actions, "reset")
		}
	case "revoking":
		actions = append(actions, "refresh", "revoke")
	case "cancelling":
		actions = append(actions, "refresh", "cancel")
	}
	if (o.State == "pending" || o.State == "revoking") && len(o.Challenges) > 0 {
		actions = append(actions, "present")
	}
	if o.RemoteID != "" {
		actions = append(actions, "cleanup")
	}
	return actions
}

func canonicalDomain(s string) (string, error) {
	name, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), "."))
	if err != nil || len(name) > 253 || !strings.Contains(name, ".") || net.ParseIP(name) != nil {
		return "", errInput
	}
	for _, label := range strings.Split(name, ".") {
		if !hostLabel.MatchString(label) {
			return "", errInput
		}
	}
	return name, nil
}

// SupportsKeyAlgorithm reports the key specifications accepted by each CA order adapter.
func SupportsKeyAlgorithm(provider, algorithm string) bool {
	switch provider {
	case "aliyun":
		return slices.Contains([]string{"RSA2048", "RSA3072", "EC256"}, algorithm)
	case "ucloud":
		return slices.Contains([]string{"RSA2048", "RSA3072", "EC256", "EC384"}, algorithm)
	case "tencentcloud", "volcengine":
		return algorithm == "RSA2048" || algorithm == "EC256"
	default:
		return false
	}
}

func (r *OrderRequest) validate(provider string) error {
	name, err := canonicalDomain(r.Domain)
	if err != nil || !SupportsKeyAlgorithm(provider, r.Algorithm) {
		return errInput
	}
	r.Domain = name
	for _, s := range []string{r.ContactName, r.Phone, r.Organization, r.Address, r.City, r.Province, r.Country, r.PostalCode, r.Department, r.Title, r.Email} {
		if !utf8.ValidString(s) || len(s) > 512 || strings.IndexFunc(s, unicode.IsControl) >= 0 {
			return errInput
		}
	}
	for _, id := range []string{r.InstanceID, r.ContactID} {
		if id != "" && !remoteIDPattern.MatchString(id) {
			return errInput
		}
	}
	if r.Email != "" {
		addr, err := mail.ParseAddress(r.Email)
		if err != nil || addr.Address != r.Email || addr.Name != "" {
			return errInput
		}
	}
	switch provider {
	case "aliyun":
	case "tencentcloud":
		if r.Email == "" {
			return errInput
		}
	case "ucloud":
		for _, s := range []string{r.Email, r.ContactName, r.Phone, r.Organization, r.Address, r.City, r.Province, r.Country, r.PostalCode, r.Department, r.Title} {
			if strings.TrimSpace(s) == "" {
				return errInput
			}
		}
	default:
		return errInput
	}
	return nil
}

func (s Snapshot) validate(o Order, recovering bool) error {
	if !slices.Contains([]string{"reserved", "pending", "issued", "failed", "cancelled", "revoked", "revoking", "cancelling", "expired"}, s.State) {
		return errProvider
	}
	// Free-plan instances may be unbound before submission, or after a cancellation.
	if s.Domain == "" {
		if recovering || (s.State != "reserved" && s.State != "cancelled") {
			return errConflict
		}
	} else if name, err := canonicalDomain(s.Domain); err != nil || name != o.Domain {
		return errConflict
	}
	return validateChallenges(s.Challenges)
}

func validateChallenges(list []Challenge) error {
	if len(list) > 32 {
		return errProvider
	}
	for _, c := range list {
		if (c.Type != "TXT" && c.Type != "CNAME") || c.Name == "" || len(c.Name) > 254 || c.Value == "" || len(c.Value) > 2048 ||
			strings.IndexFunc(c.Name, unicode.IsControl) >= 0 || strings.IndexFunc(c.Value, unicode.IsControl) >= 0 {
			return errProvider
		}
	}
	return nil
}
