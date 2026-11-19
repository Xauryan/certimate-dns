package dnscert

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/certimate-go/certimate/internal/domain"
	"github.com/volcengine/volc-sdk-golang/base"
)

// This API version supports the named free DV plan and asynchronous order
// progression. Later API versions use different methods and product plans.
const volcEndpoint = "https://open.volcengineapi.com/"

type volcIssuer struct {
	credentials base.Credentials
	project     string
	client      *http.Client
}

func newVolcengine(a *domain.Access) (Issuer, error) {
	ak, sk := field(a, "accessKeyId"), field(a, "secretAccessKey")
	if ak == "" || sk == "" {
		return nil, errInput
	}
	return &volcIssuer{
		credentials: base.Credentials{AccessKeyID: ak, SecretAccessKey: sk, Region: "cn-north-1", Service: "certificate_service"},
		project:     field(a, "projectName"), client: orderHTTPClient(),
	}, nil
}

func orderHTTPClient() *http.Client {
	return &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}

// Read through a hard limit, including when the response has no Content-Length.
func orderResponse(client *http.Client, req *http.Request, limit int64) ([]byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, errProvider
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || resp.ContentLength > limit {
		return nil, errProvider
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errProvider
	}
	return data, nil
}

func (v *volcIssuer) call(ctx context.Context, method, action string, query url.Values, body map[string]string, out any) error {
	if query == nil {
		query = url.Values{}
	}
	query.Set("Action", action)
	query.Set("Version", "2021-06-01")
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			return errInput
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, volcEndpoint+"?"+query.Encode(), bytes.NewReader(data))
	if err != nil {
		return errInput
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	v.credentials.Sign(req)
	payload, err := orderResponse(v.client, req, 1<<20)
	if err != nil {
		return err
	}
	var envelope struct {
		ResponseMetadata *struct {
			RequestID string `json:"RequestId"`
			Error     *json.RawMessage
		}
		Result json.RawMessage
	}
	if json.Unmarshal(payload, &envelope) != nil || envelope.ResponseMetadata == nil || envelope.ResponseMetadata.RequestID == "" || envelope.ResponseMetadata.Error != nil {
		return errProvider
	}
	if out != nil && (len(envelope.Result) == 0 || bytes.Equal(envelope.Result, []byte("null")) || json.Unmarshal(envelope.Result, out) != nil) {
		return errProvider
	}
	return nil
}

func (v *volcIssuer) Check(ctx context.Context) error {
	q := url.Values{"limit": {"1"}, "offset": {"0"}}
	if v.project != "" {
		q.Set("project_name", v.project)
	}
	return v.call(ctx, http.MethodGet, "CertificateGetInstance", q, nil, nil)
}

func (v *volcIssuer) Create(ctx context.Context, o OrderRequest) (string, error) {
	alg := map[string]string{"RSA2048": "rsa", "EC256": "ecc"}[o.Algorithm]
	if o.ContactID == "" || strings.TrimSpace(o.Domain) == "" || alg == "" {
		return "", errInput
	}
	body := map[string]string{"plan": "digicert_free_standard_dv", "common_name": o.Domain, "key_alg": alg, "organization_id": o.ContactID, "validation_type": "dns_txt"}
	if v.project != "" {
		body["project"] = v.project
	}
	var id string
	if err := v.call(ctx, http.MethodPost, "QuickApplyCertificate", nil, body, &id); err != nil {
		return "", err
	}
	if id == "" {
		return "", errProvider
	}
	return id, nil
}

// QuickApplyCertificate reserves and submits in the same request.
func (v *volcIssuer) Submit(context.Context, string, OrderRequest) error { return nil }

type volcInstance struct {
	ID           string `json:"id"`
	Project      string `json:"project_name"`
	InstanceType *int   `json:"instance_type"`
	Domain       string `json:"common_name"`
	Status       int    `json:"order_status"`
	Exists       int    `json:"certificate_exist"`
	Revoked      int    `json:"certificate_revoked"`
	SSL          struct {
		Certificate struct {
			Chain []string `json:"chain"`
			Key   string   `json:"private_key"`
		} `json:"certificate"`
	} `json:"ssl"`
}

func (v *volcIssuer) instance(ctx context.Context, id string) (volcInstance, error) {
	q := url.Values{"instance_id": {id}}
	if v.project != "" {
		q.Set("project_name", v.project)
	}
	var res struct{ Content []volcInstance }
	if err := v.call(ctx, http.MethodGet, "CertificateGetInstance", q, nil, &res); err != nil {
		return volcInstance{}, err
	}
	if len(res.Content) != 1 {
		return volcInstance{}, errProvider
	}
	row := res.Content[0]
	if row.ID != id || id == "" || row.InstanceType == nil || *row.InstanceType != 1 || (v.project != "" && row.Project != v.project) {
		return volcInstance{}, errProvider
	}
	return row, nil
}

func (v *volcIssuer) Inspect(ctx context.Context, id string) (Snapshot, error) {
	row, err := v.instance(ctx, id)
	if err != nil {
		return Snapshot{}, err
	}
	s := Snapshot{Domain: row.Domain}
	switch {
	case row.Revoked == 1 || row.Status == 500:
		s.State = "revoked"
	case row.Status == 400:
		s.State = "revoking"
	case row.Status == 300 && row.Exists == 1:
		s.State = "issued"
	case row.Status == 301:
		s.State = "cancelled"
	case row.Status == 302:
		s.State = "failed"
	case row.Status == 200:
		s.State = "pending"
		var validation struct {
			Type    string `json:"validation_type"`
			Domains []struct {
				Name  string `json:"validation_domain"`
				Value string
			} `json:"domains_to_be_validated"`
		}
		if err := v.call(ctx, http.MethodGet, "CertificateGetDcvParam", url.Values{"instance_id": {id}}, nil, &validation); err != nil {
			return Snapshot{}, err
		}
		kind := map[string]string{"dns_txt": "TXT", "dns_cname": "CNAME"}[validation.Type]
		for _, record := range validation.Domains {
			if kind == "" || record.Name == "" || record.Value == "" {
				return Snapshot{}, errProvider
			}
			s.Challenges = append(s.Challenges, Challenge{Name: record.Name, Type: kind, Value: record.Value})
		}
	case row.Status == 201:
		s.State = "cancelling"
	case row.Status == 100 || row.Status == 101:
		s.State = "pending"
	default:
		return Snapshot{}, errProvider
	}
	return s, nil
}

func (v *volcIssuer) Download(ctx context.Context, id string) (Material, error) {
	row, err := v.instance(ctx, id)
	if err != nil {
		return Material{}, err
	}
	pair := row.SSL.Certificate
	if row.Status != 300 || row.Exists != 1 || row.Revoked == 1 || len(pair.Chain) == 0 || pair.Key == "" {
		return Material{}, errProvider
	}
	return Material{Certificate: strings.Join(pair.Chain, "\n"), PrivateKey: pair.Key}, nil
}

func (v *volcIssuer) progress(ctx context.Context, id, action string) error {
	body := map[string]string{"action": action}
	if action == "revoke" {
		body["reason"] = "Administrator requested revocation"
	}
	return v.call(ctx, http.MethodPost, "CertificateProgressInstanceOrder", url.Values{"instance_id": {id}}, body, nil)
}

func (v *volcIssuer) Verify(ctx context.Context, id string) error { return v.progress(ctx, id, "") }
func (v *volcIssuer) Cancel(ctx context.Context, id string) error {
	return v.progress(ctx, id, "cancel")
}
func (v *volcIssuer) Revoke(ctx context.Context, id string) ([]Challenge, error) {
	return nil, v.progress(ctx, id, "revoke")
}
