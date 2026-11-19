package cdnpro

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// GetCertificateDetailResponse contains the certificate's immutable version
// numbers and the version currently serving production.
type GetCertificateDetailResponse struct {
	sdkResponseBase
	CertificateID       string `json:"certificateId"`
	VersionInProduction int32  `json:"versionInProduction"`
	Versions            []struct {
		Version     int32  `json:"version"`
		Comments    string `json:"comments"`
		Fingerprint string `json:"fingerprint"`
	} `json:"versions"`
}

func (c *Client) GetCertificateDetailWithContext(ctx context.Context, id string) (*GetCertificateDetailResponse, error) {
	if id == "" {
		return nil, fmt.Errorf("sdkerr: bad request: unset certificateId")
	}
	request, err := c.newRequest(http.MethodGet, "/cdn/certificates/"+url.PathEscape(id))
	if err != nil {
		return nil, err
	}
	result := &GetCertificateDetailResponse{}
	_, err = c.doRequestWithResult(request.SetContext(ctx), result)
	return result, err
}
