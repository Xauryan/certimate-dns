package dnscert

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/pkg/sdk3rd/ucloud/ussl"
	"github.com/ucloud/ucloud-sdk-go/ucloud/auth"
)

const ucloudPlan = "TrustAsiaC1DVFree"

type ucloudIssuer struct {
	credentials auth.Credential
	project     string
	client      *http.Client
}

func newUCloud(a *domain.Access) (Issuer, error) {
	if a == nil || field(a, "publicKey") == "" || field(a, "privateKey") == "" {
		return nil, errInput
	}
	return &ucloudIssuer{
		credentials: auth.Credential{PublicKey: field(a, "publicKey"), PrivateKey: field(a, "privateKey")},
		project:     field(a, "projectId"), client: orderHTTPClient(),
	}, nil
}

func (u *ucloudIssuer) call(ctx context.Context, action string, params map[string]any, out any) error {
	params["Action"] = action
	if u.project != "" {
		params["ProjectId"] = u.project
	}
	payload, err := json.Marshal(u.credentials.Apply(params))
	if err != nil {
		return errInput
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.ucloud.cn/", bytes.NewReader(payload))
	if err != nil {
		return errInput
	}
	req.Header.Set("Content-Type", "application/json")
	data, err := orderResponse(u.client, req, 1<<20)
	if err != nil {
		return err
	}
	var result struct {
		RetCode *int
		Action  string
	}
	if json.Unmarshal(data, &result) != nil || result.RetCode == nil || *result.RetCode != 0 || result.Action != action+"Response" {
		return errProvider
	}
	if out != nil && json.Unmarshal(data, out) != nil {
		return errProvider
	}
	return nil
}

func (u *ucloudIssuer) Check(ctx context.Context) error {
	var result struct{ TotalCount *int }
	if err := u.call(ctx, "GetCertificateList", map[string]any{"Mode": "free", "Page": 1, "PageSize": 1}, &result); err != nil {
		return err
	}
	if result.TotalCount == nil || *result.TotalCount < 0 {
		return errProvider
	}
	return nil
}

func (u *ucloudIssuer) Create(ctx context.Context, _ OrderRequest) (string, error) {
	var result struct{ CertificateID int64 }
	if err := u.call(ctx, "PurchaseCertificate", map[string]any{"CertificateBrand": "TrustAsia", "CertificateName": ucloudPlan, "DomainsCount": 1, "ValidYear": "1"}, &result); err != nil {
		return "", err
	}
	if result.CertificateID < 1 {
		return "", errProvider
	}
	return strconv.FormatInt(result.CertificateID, 10), nil
}

func ucloudID(id string) (int64, error) {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n < 1 || strconv.FormatInt(n, 10) != id {
		return 0, errInput
	}
	return n, nil
}

func (u *ucloudIssuer) Submit(ctx context.Context, id string, o OrderRequest) error {
	n, err := ucloudID(id)
	if err != nil {
		return err
	}
	var algo, key string
	switch o.Algorithm {
	case "RSA2048":
		algo, key = "RSA", "2048"
	case "RSA3072":
		algo, key = "RSA", "3072"
	case "EC256":
		algo, key = "ECDSA", "prime256v1"
	case "EC384":
		algo, key = "ECDSA", "prime384v1"
	default:
		return errInput
	}
	return u.call(ctx, "ComplementCSRInfo", map[string]any{"CertificateID": n, "Domains": o.Domain, "CSROnline": 1,
		"CSREncryptAlgo": algo, "CSRKeyParameter": key, "DVAuthMethod": "DNS", "CompanyName": o.Organization,
		"CompanyAddress": o.Address, "CompanyRegion": o.Province, "CompanyCity": o.City, "CompanyCountry": o.Country,
		"CompanyDivision": o.Department, "CompanyPhone": o.Phone, "CompanyPostalCode": o.PostalCode,
		"AdminName": o.ContactName, "AdminPhone": o.Phone, "AdminEmail": o.Email, "AdminTitle": o.Title}, nil)
}

func (u *ucloudIssuer) Inspect(ctx context.Context, id string) (Snapshot, error) {
	n, err := ucloudID(id)
	if err != nil {
		return Snapshot{}, err
	}
	var result ussl.GetCertificateDetailInfoResponse
	if err := u.call(ctx, "GetCertificateDetailInfo", map[string]any{"CertificateID": n}, &result); err != nil {
		return Snapshot{}, err
	}
	i := result.CertificateInfo
	if i == nil || int64(i.CertificateID) != n || i.StateCode == "" || (i.Mode != "purchase" && i.Mode != "free") || (i.Mode == "purchase" && i.Name != ucloudPlan) || !strings.EqualFold(i.Brand, "TrustAsia") {
		return Snapshot{}, errProvider
	}
	s := Snapshot{Domain: i.Domains}
	switch i.StateCode {
	case "COMPLETED", "RENEWED":
		s.State = "issued"
	case "REJECTED", "SECURITY_REVIEW_FAILED":
		s.State = "failed"
	case "REVOKED":
		s.State = "revoked"
	case "REVOKING":
		s.State = "revoking"
	case "CANCELLED", "CANCELED":
		s.State = "cancelled"
	case "EXPIRED":
		s.State = "expired"
	default:
		// Before ComplementCSRInfo the purchased instance has no bound name
		// or CSR. Following submission DNS validation happens asynchronously.
		if i.IssuedDate != 0 {
			return Snapshot{}, errProvider
		}
		if i.Domains == "" && i.CSR == "" {
			s.State = "reserved"
			break
		}
		if i.Domains == "" {
			return Snapshot{}, errProvider
		}
		s.State = "pending"
		s.Challenges, err = u.challenges(ctx, n, i.Domains)
		if err != nil {
			return Snapshot{}, err
		}
	}
	return s, nil
}

func (u *ucloudIssuer) challenges(ctx context.Context, id int64, domainName string) ([]Challenge, error) {
	var result struct {
		AuthMethod string
		Auths      []struct{ AuthKey, AuthType, AuthValue, Domain string }
	}
	if err := u.call(ctx, "GetDVAuthInfo", map[string]any{"CertificateID": id}, &result); err != nil {
		return nil, err
	}
	if result.AuthMethod != "DNS" {
		return nil, errProvider
	}
	out := make([]Challenge, 0, len(result.Auths))
	for _, row := range result.Auths {
		if !strings.EqualFold(strings.TrimSuffix(row.Domain, "."), strings.TrimSuffix(domainName, ".")) {
			return nil, errProvider
		}
		var kind string
		switch row.AuthType {
		case "DNS_TXT", "TXT":
			kind = "TXT"
		case "DNS_CNAME", "CNAME", "":
			kind = "CNAME" // Legacy DNS responses omit AuthType.
		default:
			return nil, errProvider
		}
		out = append(out, Challenge{Name: row.AuthKey, Type: kind, Value: row.AuthValue})
	}
	return out, validateChallenges(out)
}

func (u *ucloudIssuer) Verify(ctx context.Context, _ string) error { return ctx.Err() }

func (u *ucloudIssuer) Cancel(ctx context.Context, id string) error {
	n, err := ucloudID(id)
	if err != nil {
		return err
	}
	return u.call(ctx, "CancelCertificateOrder", map[string]any{"CertificateID": n}, nil)
}

func (u *ucloudIssuer) Revoke(ctx context.Context, id string) ([]Challenge, error) {
	n, err := ucloudID(id)
	if err != nil {
		return nil, err
	}
	return nil, u.call(ctx, "RevokeCertificate", map[string]any{"CertificateID": n, "Reason": "业务终止"}, nil)
}

func (u *ucloudIssuer) Download(ctx context.Context, id string) (Material, error) {
	n, err := ucloudID(id)
	if err != nil {
		return Material{}, err
	}
	var result struct{ CertificateURL string }
	if err := u.call(ctx, "DownloadCertificate", map[string]any{"CertificateID": n}, &result); err != nil {
		return Material{}, err
	}
	link, err := url.Parse(strings.ReplaceAll(result.CertificateURL, `\u0026`, "&"))
	if err != nil || link.Scheme != "https" || link.User != nil || link.Port() != "" && link.Port() != "443" || link.Fragment != "" {
		return Material{}, errProvider
	}
	host := strings.ToLower(link.Hostname())
	if !strings.HasSuffix(host, ".ufileos.com") && !strings.HasSuffix(host, ".ucloud.cn") && !strings.HasSuffix(host, ".ucloud.com.cn") {
		return Material{}, errProvider
	}
	// The signed storage URL has its own authorization. Do not send the API
	// credential to storage or follow a redirect with the private download link.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link.String(), nil)
	if err != nil {
		return Material{}, errProvider
	}
	archive, err := orderResponse(u.client, req, 4<<20)
	if err != nil {
		return Material{}, err
	}
	return ucloudNginxMaterial(archive)
}

func ucloudNginxMaterial(archive []byte) (Material, error) {
	return nginxArchiveMaterial(archive, func(dir string) bool { return dir == "nginx" }, ".pem")
}
