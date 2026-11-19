package dnscert

import (
	"context"
	"encoding/base64"
	"path"
	"strconv"
	"strings"

	"github.com/certimate-go/certimate/internal/domain"
	xmaps "github.com/certimate-go/certimate/pkg/utils/maps"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

type tencentIssuer struct {
	client    *ssl.Client
	projectID uint64
}

func newTencent(a *domain.Access) (Issuer, error) {
	var cfg domain.AccessConfigForTencentCloud
	if a == nil || xmaps.Populate(a.Config, &cfg) != nil ||
		cfg.SecretId == "" || cfg.SecretKey == "" || cfg.ProjectId < 0 {
		return nil, errInput
	}

	p := profile.NewClientProfile()
	p.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"
	p.HttpProfile.ReqTimeout = 25
	c, err := ssl.NewClient(common.NewCredential(cfg.SecretId, cfg.SecretKey), "", p)
	if err != nil {
		return nil, errProvider
	}
	return &tencentIssuer{client: c, projectID: uint64(cfg.ProjectId)}, nil
}

func (p *tencentIssuer) Check(ctx context.Context) error {
	req := ssl.NewDescribeCertificatesRequest()
	req.Limit = common.Uint64Ptr(1)
	req.ProjectId = &p.projectID
	res, err := p.client.DescribeCertificatesWithContext(ctx, req)
	if err != nil || res == nil || res.Response == nil || res.Response.TotalCount == nil {
		return errProvider
	}
	return nil
}

func (p *tencentIssuer) Create(ctx context.Context, in OrderRequest) (string, error) {
	if in.Domain == "" || strings.Contains(in.Domain, "*") {
		return "", errInput
	}

	req := ssl.NewApplyCertificateRequest()
	req.DvAuthMethod = common.StringPtr("DNS")
	req.DomainName = &in.Domain
	req.PackageType = common.StringPtr("83") // TrustAsia C1 DV Free
	req.ProjectId = &p.projectID
	if in.Email != "" {
		req.ContactEmail = &in.Email
	}
	if in.Phone != "" {
		req.ContactPhone = &in.Phone
	}
	switch in.Algorithm {
	case "RSA2048":
		req.CsrEncryptAlgo = common.StringPtr("RSA")
		req.CsrKeyParameter = common.StringPtr("2048")
	case "EC256":
		req.CsrEncryptAlgo = common.StringPtr("ECC")
		req.CsrKeyParameter = common.StringPtr("prime256v1")
	default:
		return "", errInput
	}

	res, err := p.client.ApplyCertificateWithContext(ctx, req)
	if err != nil || res == nil || res.Response == nil || tcString(res.Response.CertificateId) == "" {
		return "", errProvider
	}
	return *res.Response.CertificateId, nil
}

// ApplyCertificate submits the order in the same request that allocates its ID.
func (p *tencentIssuer) Submit(context.Context, string, OrderRequest) error { return nil }

func tcString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func (p *tencentIssuer) describe(ctx context.Context, id string) (*ssl.DescribeCertificateResponseParams, error) {
	req := ssl.NewDescribeCertificateRequest()
	req.CertificateId = &id
	res, err := p.client.DescribeCertificateWithContext(ctx, req)
	if err != nil || res == nil || res.Response == nil {
		return nil, errProvider
	}
	data := res.Response
	if id == "" || tcString(data.CertificateId) != id || tcString(data.ProjectId) != strconv.FormatUint(p.projectID, 10) ||
		tcString(data.PackageType) != "83" || tcString(data.Domain) == "" || data.Status == nil {
		return nil, errProvider
	}
	return data, nil
}

func (p *tencentIssuer) Inspect(ctx context.Context, id string) (Snapshot, error) {
	data, err := p.describe(ctx, id)
	if err != nil {
		return Snapshot{}, err
	}
	out := Snapshot{Domain: *data.Domain}
	var rows []*ssl.DvAuths
	switch *data.Status {
	case 0, 4, 5, 8, 11, 13, 15:
		out.State = "pending"
		if detail := data.DvAuthDetail; detail != nil {
			rows = detail.DvAuths
			if len(rows) == 0 && tcString(detail.DvAuthKey) != "" {
				rows = []*ssl.DvAuths{{DvAuthKey: detail.DvAuthKey, DvAuthValue: detail.DvAuthValue, DvAuthDomain: detail.DvAuthDomain, DvAuthPath: detail.DvAuthPath}}
			}
		}
	case 1:
		out.State = "issued"
	case 2:
		out.State = "failed"
	case 3:
		out.State = "expired"
	case 6:
		out.State = "cancelling"
	case 7, 14:
		out.State = "cancelled"
	case 9, 12:
		out.State = "revoking"
		rows = data.DvRevokeAuthDetail
	case 10:
		out.State = "revoked"
	default:
		return Snapshot{}, errProvider
	}
	for _, row := range rows {
		if row == nil || tcString(row.DvAuthPath) != "" || tcString(row.DvAuthKey) == "" || tcString(row.DvAuthValue) == "" {
			continue
		}
		kind := strings.ToUpper(tcString(row.DvAuthVerifyType))
		if kind == "" {
			// Older responses for this product omit the record type.
			kind = "CNAME"
			if out.State == "revoking" {
				kind = "TXT"
			}
		}
		if kind == "CNAME" || kind == "TXT" {
			out.Challenges = append(out.Challenges, Challenge{Name: tencentChallengeName(*row.DvAuthKey, tcString(row.DvAuthDomain)), Type: kind, Value: *row.DvAuthValue})
		}
	}
	return out, nil
}

func (p *tencentIssuer) Verify(ctx context.Context, id string) error {
	data, err := p.describe(ctx, id)
	if err != nil {
		return err
	}
	if *data.Status == 1 {
		return nil
	}
	if *data.Status != 0 && *data.Status != 4 {
		return errInput
	}
	req := ssl.NewCompleteCertificateRequest()
	req.CertificateId = &id
	res, err := p.client.CompleteCertificateWithContext(ctx, req)
	if err != nil || res == nil || res.Response == nil || tcString(res.Response.CertificateId) != id {
		return errProvider
	}
	return nil
}

func (p *tencentIssuer) Download(ctx context.Context, id string) (Material, error) {
	detail, err := p.describe(ctx, id)
	if err != nil {
		return Material{}, err
	}
	if *detail.Status != 1 {
		return Material{}, errProvider
	}
	req := ssl.NewDownloadCertificateRequest()
	req.CertificateId = &id
	res, err := p.client.DownloadCertificateWithContext(ctx, req)
	if err != nil || res == nil || res.Response == nil || tcString(res.Response.ContentType) != "application/zip" {
		return Material{}, errProvider
	}
	const maxArchive = 4 << 20
	encoded := tcString(res.Response.Content)
	if encoded == "" || len(encoded) > base64.StdEncoding.EncodedLen(maxArchive) {
		return Material{}, errProvider
	}
	archive, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(archive) > maxArchive {
		return Material{}, errProvider
	}
	// Both the legacy Nginx folder and <domain>_nginx contain the bundled
	// leaf and intermediates in the .crt file. The .pem is a duplicate.
	return nginxArchiveMaterial(archive, func(dir string) bool {
		folder := path.Base(dir)
		return folder == "nginx" || strings.EqualFold(folder, *detail.Domain+"_nginx")
	}, "_bundle.crt")
}

func (p *tencentIssuer) Cancel(ctx context.Context, id string) error {
	data, err := p.describe(ctx, id)
	if err != nil {
		return err
	}
	switch *data.Status {
	case 6, 7:
		return nil
	case 0, 4, 13:
	default:
		return errInput
	}
	req := ssl.NewCancelAuditCertificateRequest()
	req.CertificateId = &id
	res, err := p.client.CancelAuditCertificateWithContext(ctx, req)
	if err != nil || res == nil || res.Response == nil || res.Response.Result == nil || !*res.Response.Result {
		return errProvider
	}
	return nil
}

func (p *tencentIssuer) Revoke(ctx context.Context, id string) ([]Challenge, error) {
	data, err := p.describe(ctx, id)
	if err != nil {
		return nil, err
	}
	if *data.Status != 1 {
		return nil, errInput
	}
	req := ssl.NewRevokeCertificateRequest()
	req.CertificateId = &id
	res, err := p.client.RevokeCertificateWithContext(ctx, req)
	if err != nil || res == nil || res.Response == nil || tcString(res.Response.RequestId) == "" {
		return nil, errProvider
	}
	var challenges []Challenge
	for _, row := range res.Response.RevokeDomainValidateAuths {
		if row == nil || tcString(row.DomainValidateAuthPath) != "" {
			continue // The DNS order UI handles DNS challenges only.
		}
		name, value := tcString(row.DomainValidateAuthKey), tcString(row.DomainValidateAuthValue)
		if name == "" || value == "" {
			continue
		}
		name = tencentChallengeName(name, tcString(row.DomainValidateAuthDomain))
		challenges = append(challenges, Challenge{Name: name, Type: "TXT", Value: value})
	}
	return challenges, nil
}

// DvAuthKey can be absolute or a host label relative to DvAuthDomain.
func tencentChallengeName(key, domain string) string {
	name := strings.TrimSuffix(key, ".")
	zone := strings.TrimSuffix(domain, ".")
	if zone == "" || strings.HasSuffix(key, ".") || strings.EqualFold(name, zone) || strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(zone)) {
		return name
	}
	if name == "@" {
		return zone
	}
	// DvAuthDomain may be the certificate FQDN while the returned DCV
	// record is already qualified under its parent. The API supplies the
	// domain separately for single-label keys.
	if strings.Contains(name, ".") {
		return name
	}
	return name + "." + zone
}
