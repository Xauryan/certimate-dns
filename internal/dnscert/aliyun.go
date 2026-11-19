package dnscert

import (
	"context"
	"strconv"
	"strings"

	cas "github.com/alibabacloud-go/cas-20200407/v4/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	"github.com/alibabacloud-go/tea/dara"

	"github.com/certimate-go/certimate/internal/domain"
)

type aliyunIssuer struct {
	client *cas.Client
	group  string
}

func newAliyun(a *domain.Access) (Issuer, error) {
	id, secret := field(a, "accessKeyId"), field(a, "accessKeySecret")
	if id == "" || secret == "" {
		return nil, errInput
	}
	client, err := cas.NewClient(&openapi.Config{AccessKeyId: &id, AccessKeySecret: &secret,
		Endpoint: dara.String("cas.aliyuncs.com"), RegionId: dara.String("cn-hangzhou"),
		ConnectTimeout: dara.Int(5000), ReadTimeout: dara.Int(20000),
	})
	if err != nil {
		return nil, errProvider
	}
	return &aliyunIssuer{client, field(a, "resourceGroupId")}, nil
}

func (p *aliyunIssuer) list(ctx context.Context, page, size int32) (*cas.ListInstancesResponseBody, error) {
	req := &cas.ListInstancesRequest{CurrentPage: &page, ShowSize: &size, Status: dara.String("inactive"), InstanceType: dara.String("TEST")}
	if p.group != "" {
		req.ResourceGroupId = &p.group
	}
	r, err := p.client.ListInstancesWithContext(ctx, req, &dara.RuntimeOptions{})
	if err != nil || r == nil || r.Body == nil || r.Body.TotalCount == nil {
		return nil, errProvider
	}
	return r.Body, nil
}

func (p *aliyunIssuer) Check(ctx context.Context) error {
	_, err := p.list(ctx, 1, 1)
	return err
}

func (p *aliyunIssuer) detail(ctx context.Context, id string) (*cas.GetInstanceDetailResponseBody, error) {
	if id == "" {
		return nil, errInput
	}
	r, err := p.client.GetInstanceDetailWithContext(ctx, &cas.GetInstanceDetailRequest{InstanceId: &id}, &dara.RuntimeOptions{})
	if err != nil || r == nil || r.Body == nil {
		return nil, errProvider
	}
	d := r.Body
	if dara.StringValue(d.InstanceId) != id || dara.StringValue(d.InstanceType) != "TEST" || p.group != "" && dara.StringValue(d.ResourceGroupId) != p.group {
		return nil, errProvider
	}
	return d, nil
}

func (p *aliyunIssuer) Create(ctx context.Context, req OrderRequest) (string, error) {
	return p.selectInstance(ctx, req, nil)
}

func (p *aliyunIssuer) selectInstance(ctx context.Context, req OrderRequest, skip map[string]bool) (string, error) {
	if req.InstanceID != "" {
		if skip[req.InstanceID] {
			return "", errConflict
		}
		d, err := p.detail(ctx, req.InstanceID)
		if err != nil {
			return "", err
		}
		if !aliAvailable(d.Status, d.Domain, req.Domain) {
			return "", errProvider
		}
		return req.InstanceID, nil
	}
	const pageSize = 100
	for page := int32(1); ; page++ {
		b, err := p.list(ctx, page, pageSize)
		if err != nil {
			return "", err
		}
		for _, item := range b.InstanceList {
			if item == nil || dara.StringValue(item.InstanceType) != "TEST" || !aliAvailable(item.Status, item.Domain, req.Domain) {
				continue
			}
			id := dara.StringValue(item.InstanceId)
			if id != "" && !skip[id] && (p.group == "" || dara.StringValue(item.ResourceGroupId) == p.group) {
				return id, nil
			}
		}
		if len(b.InstanceList) == 0 || int64(page)*pageSize >= *b.TotalCount {
			return "", errProvider
		}
	}
}

func aliAvailable(status, bound *string, domain string) bool {
	return dara.StringValue(status) == "inactive" && (dara.StringValue(bound) == "" || strings.EqualFold(dara.StringValue(bound), domain))
}

func (p *aliyunIssuer) Submit(ctx context.Context, id string, req OrderRequest) error {
	if req.Domain == "" {
		return errInput
	}
	algorithm := map[string]string{"RSA2048": "RSA_2048", "RSA3072": "RSA_3072", "EC256": "ECC_256"}[req.Algorithm]
	if algorithm == "" {
		return errInput
	}
	d, err := p.detail(ctx, id)
	if err != nil {
		return err
	}
	if !aliAvailable(d.Status, d.Domain, req.Domain) {
		return errProvider
	}
	var contactID int64
	if req.ContactID != "" {
		contactID, err = strconv.ParseInt(req.ContactID, 10, 64)
		if err != nil || contactID < 1 {
			return errInput
		}
	} else if len(d.ContactIdList) > 0 && dara.Int64Value(d.ContactIdList[0]) > 0 {
		contactID = *d.ContactIdList[0]
	} else {
		contacts, err := p.client.ListContactWithContext(ctx, &cas.ListContactRequest{CurrentPage: dara.Int32(1), ShowSize: dara.Int32(1)}, &dara.RuntimeOptions{})
		if err != nil || contacts == nil || contacts.Body == nil || len(contacts.Body.ContactList) == 0 || contacts.Body.ContactList[0] == nil || dara.Int64Value(contacts.Body.ContactList[0].ContactId) < 1 {
			return errProvider
		}
		contactID = *contacts.Body.ContactList[0].ContactId
	}
	update := &cas.UpdateInstanceRequest{InstanceId: &id, Domain: &req.Domain, ContactIdList: []*int64{&contactID}, KeyAlgorithm: &algorithm,
		AutoReissue: dara.String("disable"), GenerateCsrMethod: dara.String("online"), ValidationMethod: dara.String("DNS")}
	if r, err := p.client.UpdateInstanceWithContext(ctx, update, &dara.RuntimeOptions{}); err != nil || r == nil || r.Body == nil || dara.StringValue(r.Body.RequestId) == "" {
		return errProvider
	}
	if r, err := p.client.ApplyCertificateWithContext(ctx, &cas.ApplyCertificateRequest{InstanceId: &id}, &dara.RuntimeOptions{}); err != nil || r == nil || r.Body == nil || dara.StringValue(r.Body.RequestId) == "" {
		return errProvider
	}
	return nil
}

func (p *aliyunIssuer) Inspect(ctx context.Context, id string) (Snapshot, error) {
	d, err := p.detail(ctx, id)
	if err != nil {
		return Snapshot{}, err
	}
	s := Snapshot{Domain: dara.StringValue(d.Domain)}
	if dara.StringValue(d.CertificateStatus) == "revoked" {
		s.State = "revoked"
		return s, nil
	}
	switch dara.StringValue(d.Status) {
	case "normal", "willExpire":
		if dara.Int32Value(d.CertificateId) <= 0 {
			return Snapshot{}, errProvider
		}
		s.State = "issued"
	case "expired":
		s.State = "expired"
	case "refund":
		s.State = "cancelled"
	case "closed":
		s.State = "failed"
	case "inactive":
		s.State = "reserved"
		// ApplyCertificate is asynchronous. The instance ID is the task key in the CAS V2 protocol.
		if s.Domain != "" {
			r, err := p.client.GetTaskAttributeWithContext(ctx, &cas.GetTaskAttributeRequest{TaskId: &id, TaskType: dara.String("ApplyCertificate")}, &dara.RuntimeOptions{})
			if err != nil || r == nil || r.Body == nil {
				return Snapshot{}, errProvider
			}
			switch dara.StringValue(r.Body.TaskStatus) {
			case "failed":
				s.State = "failed"
			case "processing", "success":
				s.State = "pending"
			default:
				return Snapshot{}, errProvider
			}
		}
	case "pending":
		s.State = "pending"
	default:
		return Snapshot{}, errProvider
	}
	if s.State == "pending" {
		for _, c := range d.DomainValidationList {
			if c == nil {
				return Snapshot{}, errProvider
			}
			root := strings.TrimSuffix(dara.StringValue(c.RootDomain), ".")
			name := strings.TrimSuffix(dara.StringValue(c.ValidationKey), ".")
			kind := strings.ToUpper(dara.StringValue(c.ValidationType))
			if root == "" || name == "" || (kind != "TXT" && kind != "CNAME") || dara.StringValue(c.ValidationValue) == "" {
				return Snapshot{}, errProvider
			}
			if name == "@" {
				name = root
			} else if !strings.EqualFold(name, root) && !strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(root)) {
				name += "." + root
			}
			s.Challenges = append(s.Challenges, Challenge{Name: name, Type: kind, Value: *c.ValidationValue})
		}
	}
	return s, nil
}

// CAS validates the DNS records automatically after ApplyCertificate.
func (*aliyunIssuer) Verify(ctx context.Context, _ string) error { return ctx.Err() }

func (p *aliyunIssuer) Download(ctx context.Context, id string) (Material, error) {
	d, err := p.detail(ctx, id)
	if err != nil {
		return Material{}, err
	}
	certID := int64(dara.Int32Value(d.CertificateId))
	if certID < 1 || dara.StringValue(d.CertificateStatus) == "revoked" || (dara.StringValue(d.Status) != "normal" && dara.StringValue(d.Status) != "willExpire") {
		return Material{}, errProvider
	}
	r, err := p.client.GetUserCertificateDetailWithContext(ctx, &cas.GetUserCertificateDetailRequest{CertId: &certID, CertFilter: dara.Bool(false)}, &dara.RuntimeOptions{})
	if err != nil || r == nil || r.Body == nil {
		return Material{}, errProvider
	}
	b := r.Body
	if dara.StringValue(b.InstanceId) != id || dara.Int64Value(b.Id) != certID || dara.StringValue(b.Cert) == "" || dara.StringValue(b.Key) == "" {
		return Material{}, errProvider
	}
	return Material{Certificate: *b.Cert, PrivateKey: *b.Key}, nil
}

func (p *aliyunIssuer) Cancel(ctx context.Context, id string) error {
	d, err := p.detail(ctx, id)
	if err != nil {
		return err
	}
	if dara.StringValue(d.Status) == "inactive" && dara.StringValue(d.Domain) == "" {
		return nil
	}
	if dara.StringValue(d.Status) != "pending" {
		return errProvider
	}
	if r, err := p.client.CancelPendingCertificateWithContext(ctx, &cas.CancelPendingCertificateRequest{InstanceId: &id}, &dara.RuntimeOptions{}); err != nil || r == nil || r.Body == nil || dara.StringValue(r.Body.RequestId) == "" {
		return errProvider
	}
	return nil
}

func (p *aliyunIssuer) Revoke(ctx context.Context, id string) ([]Challenge, error) {
	d, err := p.detail(ctx, id)
	if err != nil {
		return nil, err
	}
	certID := int64(dara.Int32Value(d.CertificateId))
	if dara.StringValue(d.CertificateStatus) == "revoked" {
		return nil, nil
	}
	if certID <= 0 || (dara.StringValue(d.Status) != "normal" && dara.StringValue(d.Status) != "willExpire") {
		return nil, errProvider
	}
	if r, err := p.client.RevokeCertificateWithContext(ctx, &cas.RevokeCertificateRequest{InstanceId: &id, CertificateId: &certID}, &dara.RuntimeOptions{}); err != nil || r == nil || r.Body == nil || dara.StringValue(r.Body.RequestId) == "" {
		return nil, errProvider
	}
	return nil, nil
}
