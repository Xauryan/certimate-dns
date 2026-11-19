package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

type ValidationRecord struct {
	Status   string `json:"status,omitempty"`
	TXTName  string `json:"txt_name,omitempty"`
	TXTValue string `json:"txt_value,omitempty"`
	CNAME    string `json:"cname_name,omitempty"`
	Target   string `json:"cname_target,omitempty"`
	HTTPURL  string `json:"http_url,omitempty"`
	HTTPBody string `json:"http_body,omitempty"`
}

type HostnameSSL struct {
	Status   string `json:"status,omitempty"`
	Method   string `json:"method,omitempty"`
	Type     string `json:"type,omitempty"`
	Settings struct {
		MinTLS string `json:"min_tls_version,omitempty"`
	} `json:"settings"`
	Records []ValidationRecord `json:"validation_records,omitempty"`
}

type Hostname struct {
	ID        string      `json:"id"`
	Hostname  string      `json:"hostname"`
	Status    string      `json:"status"`
	Origin    string      `json:"custom_origin_server,omitempty"`
	SSL       HostnameSSL `json:"ssl"`
	Ownership struct {
		Type  string `json:"type,omitempty"`
		Name  string `json:"name,omitempty"`
		Value string `json:"value,omitempty"`
	} `json:"ownership_verification"`
	OwnershipHTTP struct {
		URL  string `json:"http_url,omitempty"`
		Body string `json:"http_body,omitempty"`
	} `json:"ownership_verification_http"`
}

type HostnameInput struct {
	Hostname string `json:"hostname"`
	// An omitted origin on edit preserves the current origin. An empty origin resets it.
	Origin *string `json:"origin"`
	Method string  `json:"method"`
	MinTLS string  `json:"minTLS"`
}

func hostPath(zone string) string { return "/zones/" + zone + "/custom_hostnames" }

func (c *Client) Hostnames(ctx context.Context, zone string, page int) (*DNSPage[Hostname], error) {
	if !dnsID.MatchString(zone) {
		return nil, ErrInvalidDNSRequest
	}
	return pageResult[Hostname](ctx, c, hostPath(zone), page, nil)
}

func sslInput(method, minTLS string) (map[string]any, error) {
	if method != "http" && method != "txt" {
		return nil, ErrInvalidDNSRequest
	}
	ssl := map[string]any{"method": method, "type": "dv"}
	if minTLS != "" {
		switch minTLS {
		case "1.0", "1.1", "1.2", "1.3":
		default:
			return nil, ErrInvalidDNSRequest
		}
		ssl["settings"] = map[string]string{"min_tls_version": minTLS}
	}
	return ssl, nil
}

func (c *Client) SaveHostname(ctx context.Context, zone, id string, in HostnameInput) (Hostname, error) {
	if !dnsID.MatchString(zone) || (id != "" && !uuidPattern.MatchString(id)) {
		return Hostname{}, ErrInvalidDNSRequest
	}
	body := map[string]any{}
	if in.Origin != nil {
		if *in.Origin != "" {
			name, err := hostName(*in.Origin)
			if err != nil {
				return Hostname{}, err
			}
			body["custom_origin_server"] = name
		} else if id != "" {
			body["custom_origin_server"] = nil
		}
	}
	if id != "" && (in.Method != "" || in.MinTLS != "") {
		ssl, err := c.currentSSL(ctx, zone, id)
		if err != nil {
			return Hostname{}, err
		}
		if in.Method != "" {
			if _, err := sslInput(in.Method, ""); err != nil {
				return Hostname{}, err
			}
			ssl["method"], _ = json.Marshal(in.Method)
		}
		if in.MinTLS != "" {
			if _, err := sslInput("txt", in.MinTLS); err != nil {
				return Hostname{}, err
			}
			settings := map[string]json.RawMessage{}
			if len(ssl["settings"]) > 0 && string(ssl["settings"]) != "null" {
				if err := json.Unmarshal(ssl["settings"], &settings); err != nil {
					return Hostname{}, errors.New("invalid hostname TLS settings")
				}
			}
			settings["min_tls_version"], _ = json.Marshal(in.MinTLS)
			ssl["settings"], _ = json.Marshal(settings)
		}
		body["ssl"] = ssl
	} else if id == "" {
		ssl, err := sslInput(in.Method, in.MinTLS)
		if err != nil {
			return Hostname{}, err
		}
		body["ssl"] = ssl
	}
	path := hostPath(zone)
	method := http.MethodPost
	if id == "" {
		name, err := hostName(in.Hostname)
		if err != nil {
			return Hostname{}, err
		}
		body["hostname"] = name
	} else {
		if in.Hostname != "" || len(body) == 0 {
			return Hostname{}, ErrInvalidDNSRequest
		}
		method = http.MethodPatch
		path += "/" + id
	}
	return getResult[Hostname](ctx, c, method, path, body)
}

// Refresh DV by resending the existing issuance settings. Never send certificates,
// private keys, validation challenges or status fields back in the PATCH.
func (c *Client) RevalidateHostname(ctx context.Context, zone, id string) (Hostname, error) {
	if !dnsID.MatchString(zone) || !uuidPattern.MatchString(id) {
		return Hostname{}, ErrInvalidDNSRequest
	}
	ssl, err := c.currentSSL(ctx, zone, id)
	if err != nil {
		return Hostname{}, err
	}
	return getResult[Hostname](ctx, c, http.MethodPatch, hostPath(zone)+"/"+id, map[string]any{"ssl": ssl})
}

func (c *Client) currentSSL(ctx context.Context, zone, id string) (map[string]json.RawMessage, error) {
	path := hostPath(zone) + "/" + id
	current, err := getResult[struct {
		SSL map[string]json.RawMessage `json:"ssl"`
	}](ctx, c, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var method, kind string
	_ = json.Unmarshal(current.SSL["method"], &method)
	_ = json.Unmarshal(current.SSL["type"], &kind)
	if method == "" || kind != "dv" {
		return nil, errors.New("hostname does not have a managed DV certificate")
	}
	ssl := map[string]json.RawMessage{}
	for _, key := range []string{"method", "type", "settings", "wildcard", "certificate_authority", "bundle_method", "cloudflare_branding"} {
		if v, ok := current.SSL[key]; ok {
			ssl[key] = v
		}
	}
	return ssl, nil
}

func (c *Client) DeleteHostname(ctx context.Context, zone, id string) error {
	if !dnsID.MatchString(zone) || !uuidPattern.MatchString(id) {
		return ErrInvalidDNSRequest
	}
	_, err := getResult[struct{}](ctx, c, http.MethodDelete, hostPath(zone)+"/"+id, nil)
	return err
}

type Origin struct {
	Origin string `json:"origin"`
	Status string `json:"status,omitempty"`
}

func (c *Client) FallbackOrigin(ctx context.Context, zone, method, origin string) (Origin, error) {
	if !dnsID.MatchString(zone) {
		return Origin{}, ErrInvalidDNSRequest
	}
	var body any
	switch method {
	case http.MethodGet, http.MethodDelete:
	case http.MethodPut:
		name, err := hostName(origin)
		if err != nil {
			return Origin{}, err
		}
		body = Origin{Origin: name}
	default:
		return Origin{}, ErrInvalidDNSRequest
	}
	out, err := getResult[Origin](ctx, c, method, hostPath(zone)+"/fallback_origin", body)
	var status *ProviderStatusError
	if method != http.MethodPut && errors.As(err, &status) && status.Status == 404 {
		return Origin{}, nil
	}
	return out, err
}

type Delegation struct {
	UUID string `json:"uuid"`
}

func (c *Client) Delegation(ctx context.Context, zone string) (Delegation, error) {
	if !dnsID.MatchString(zone) {
		return Delegation{}, ErrInvalidDNSRequest
	}
	return getResult[Delegation](ctx, c, http.MethodGet, "/zones/"+zone+"/dcv_delegation/uuid", nil)
}
