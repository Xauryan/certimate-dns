package btpanel

import (
	"context"
	"errors"
	"net/http"
)

// SetDockerSiteCertificate updates the Docker site managed by the panel.
// LinuxPanel 11.0.0: mod/project/docker/sites/sitesManage.py, SitesManage.set_ssl.
func (c *Client) SetDockerSiteCertificate(ctx context.Context, site, cert, key string) error {
	return c.setDomainCertificate(ctx, "/mod/docker/com/set_ssl", map[string]string{
		"site_name": site, "csr": cert, "key": key,
	})
}

// SetMailDomainCertificate uses the installed mail_sys plugin's certificate operation.
// https://download.bt.cn/install/plugin/mail_sys_en/mail_sys_main.py
func (c *Client) SetMailDomainCertificate(ctx context.Context, domain, cert, key string) error {
	return c.setDomainCertificate(ctx, "/plugin?action=a&name=mail_sys&s=set_mail_certificate_multiple", map[string]string{
		"act": "add", "domain": domain, "csr": cert, "key": key,
	})
}

func (c *Client) setDomainCertificate(ctx context.Context, endpoint string, fields map[string]string) error {
	req, err := c.newRequest(http.MethodPost, endpoint, fields)
	if err != nil {
		return err
	}
	var result sdkResponseBase
	if _, err := c.doRequestWithResult(req.SetContext(ctx), &result); err != nil {
		return err
	}
	if result.Status == nil || !*result.Status {
		return errors.New("panel did not confirm certificate installation")
	}
	return nil
}
