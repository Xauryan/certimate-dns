package btpanelgo

import (
	"context"
	"fmt"
	"net/http"
)

// SetSiteDomainSSL binds an uploaded PFX document to a domain in IIS.
// DNSMgr btwin::deployIISSite uses /site/set_site_domain_ssl with domain/path/password.
func (c *Client) SetSiteDomainSSL(ctx context.Context, domain, path, password string) error {
	req, err := c.newRequest(http.MethodPost, "/site/set_site_domain_ssl", map[string]string{
		"domain": domain, "path": path, "password": password,
	}, false)
	if err != nil {
		return err
	}
	var result sdkResponseBase
	if _, err := c.doRequestWithResult(req.SetContext(ctx), &result); err != nil {
		return err
	}
	if !result.Confirmed() {
		return fmt.Errorf("panel did not confirm IIS domain binding")
	}
	return nil
}

// RemoveFile removes one named file. The Windows 8.5.2 web client sends
// files/remove_file with filename when deleting a certificate file.
func (c *Client) RemoveFile(ctx context.Context, filename string) error {
	req, err := c.newRequest(http.MethodPost, "/files/remove_file", map[string]string{"filename": filename}, false)
	if err != nil {
		return err
	}
	var result sdkResponseBase
	if _, err := c.doRequestWithResult(req.SetContext(ctx), &result); err != nil {
		return err
	}
	if !result.Confirmed() {
		return fmt.Errorf("panel did not confirm file removal")
	}
	return nil
}
