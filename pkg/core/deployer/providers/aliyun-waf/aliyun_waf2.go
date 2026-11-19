package aliyunwaf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	"github.com/alibabacloud-go/tea/dara"
)

// WAF 2.0 uses the 2019-09-10 RPC API and a numeric CAS certificate ID.
// https://help.aliyun.com/en/waf/web-application-firewall-2-0/developer-reference/api-createcertificatebycertificateid
func (d *Deployer) deployToWAF2(ctx context.Context, certPEM, keyPEM string) error {
	region := d.config.Region
	if region != "cn-hangzhou" && region != "ap-southeast-1" {
		return errors.New("WAF 2.0 requires cn-hangzhou or ap-southeast-1")
	}
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return errors.New("invalid certificate or mismatched private key")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return errors.New("invalid leaf certificate")
	}
	var domains []string
	for _, raw := range strings.FieldsFunc(d.config.Domain, func(r rune) bool { return r == ',' || r == '\n' }) {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if host == "" || slices.Contains(domains, host) {
			continue
		}
		if strings.HasPrefix(host, "*.") {
			if !slices.ContainsFunc(leaf.DNSNames, func(name string) bool { return strings.EqualFold(name, host) }) {
				return fmt.Errorf("certificate does not cover wildcard %q", host)
			}
		} else if leaf.VerifyHostname(host) != nil {
			return fmt.Errorf("certificate does not cover %q", host)
		}
		domains = append(domains, host)
	}
	if len(domains) == 0 {
		return errors.New("at least one protected WAF 2.0 domain is required")
	}

	selection := map[string]*string{}
	if d.config.InstanceId != "" {
		selection["InstanceId"] = &d.config.InstanceId
	}
	if d.config.ResourceGroupId != "" {
		selection["ResourceGroupId"] = &d.config.ResourceGroupId
	}
	var instance struct {
		InstanceInfo struct {
			InstanceId string
			Status     int
		}
	}
	if err := d.callWAF2(ctx, http.MethodGet, "DescribeInstanceInfo", selection, &instance); err != nil {
		return err
	}
	id := instance.InstanceInfo.InstanceId
	if id == "" || instance.InstanceInfo.Status != 1 || d.config.InstanceId != "" && id != d.config.InstanceId {
		return errors.New("active WAF 2.0 instance not found")
	}
	for _, host := range domains {
		var detail struct {
			Domain *struct{ ResourceGroupId string }
		}
		if err := d.callWAF2(ctx, http.MethodGet, "DescribeDomain", map[string]*string{"InstanceId": &id, "Domain": &host}, &detail); err != nil {
			return err
		}
		if detail.Domain == nil || d.config.ResourceGroupId != "" && detail.Domain.ResourceGroupId != d.config.ResourceGroupId {
			return fmt.Errorf("WAF 2.0 domain %q unavailable in the selected group", host)
		}
	}
	uploaded, err := d.sdkCertmgr.Upload(ctx, certPEM, keyPEM)
	if err != nil || uploaded == nil {
		return errors.New("CAS certificate upload failed")
	}
	certID, err := strconv.ParseInt(uploaded.CertId, 10, 64)
	if err != nil || certID <= 0 {
		return errors.New("CAS did not return a numeric certificate ID")
	}
	for i, host := range domains {
		var res struct{ CertificateId int64 }
		err := d.callWAF2(ctx, http.MethodPost, "CreateCertificateByCertificateId", map[string]*string{"Domain": &host, "InstanceId": &id, "CertificateId": &uploaded.CertId}, &res)
		if err != nil || res.CertificateId != certID {
			return fmt.Errorf("WAF 2.0 did not confirm certificate binding for %s (%d of %d confirmed)", host, i, len(domains))
		}
	}
	return nil
}

func (d *Deployer) callWAF2(ctx context.Context, method, action string, query map[string]*string, out any) error {
	result, err := d.sdkClient.DoRPCRequestWithCtx(ctx, &action, dara.String("2019-09-10"), dara.String("HTTPS"), &method, dara.String("AK"), dara.String("string"), &openapi.OpenApiRequest{Query: query}, &dara.RuntimeOptions{})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("WAF 2.0 %s request failed", action)
	}
	body, ok := result["body"].(string)
	if !ok || json.Unmarshal([]byte(body), out) != nil {
		return fmt.Errorf("WAF 2.0 returned an invalid %s response", action)
	}
	return nil
}
