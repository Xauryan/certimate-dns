package cloudflare

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	jose "github.com/go-jose/go-jose/v4"
	"net/http"
	"net/netip"
	"strings"
	"unicode/utf8"
)

type Tunnel struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Source string `json:"config_src"`
}

func (c *Client) Tunnels(ctx context.Context, account string, page int) (*DNSPage[Tunnel], error) {
	if !dnsID.MatchString(account) {
		return nil, ErrInvalidDNSRequest
	}
	return pageResult[Tunnel](ctx, c, "/accounts/"+account+"/cfd_tunnel", page, map[string]string{"is_deleted": "false"})
}

func tunnelPath(account, tunnel string) (string, error) {
	if !dnsID.MatchString(account) || !uuidPattern.MatchString(tunnel) {
		return "", ErrInvalidDNSRequest
	}
	return "/accounts/" + account + "/cfd_tunnel/" + tunnel, nil
}

// CreateTunnel selects remote configuration, so cloudflared can use a connector token.
func (c *Client) CreateTunnel(ctx context.Context, account, name string) (Tunnel, error) {
	name = strings.TrimSpace(name)
	if !dnsID.MatchString(account) || name == "" || len(name) > 100 {
		return Tunnel{}, ErrInvalidDNSRequest
	}
	return getResult[Tunnel](ctx, c, http.MethodPost, "/accounts/"+account+"/cfd_tunnel", map[string]string{"name": name, "config_src": "cloudflare"})
}

// EncryptedTunnelToken returns a compact JWE for the connector operator.
// A token never enters an application response, log, or database in plaintext.
func (c *Client) EncryptedTunnelToken(ctx context.Context, account, tunnel, recipientPublicKeyPEM string) (string, error) {
	path, err := tunnelPath(account, tunnel)
	if err != nil {
		return "", err
	}
	if len(recipientPublicKeyPEM) > 4096 {
		return "", ErrInvalidDNSRequest
	}
	block, rest := pem.Decode([]byte(recipientPublicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" || strings.TrimSpace(string(rest)) != "" {
		return "", ErrInvalidDNSRequest
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	pub, ok := key.(*rsa.PublicKey)
	if err != nil || !ok || pub.N.BitLen() < 2048 || pub.N.BitLen() > 4096 {
		return "", ErrInvalidDNSRequest
	}
	enc, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: pub}, nil)
	if err != nil {
		return "", ErrInvalidDNSRequest
	}
	token, err := getResult[string](ctx, c, http.MethodGet, path+"/token", nil)
	if err != nil {
		return "", err
	}
	if token == "" {
		return "", errors.New("Cloudflare returned an empty connector token")
	}
	encrypted, err := enc.Encrypt([]byte(token))
	if err != nil {
		return "", errors.New("could not encrypt the connector token")
	}
	return encrypted.CompactSerialize()
}

func (c *Client) EditTunnel(ctx context.Context, account, tunnel, name string) (Tunnel, error) {
	path, err := tunnelPath(account, tunnel)
	if err != nil {
		return Tunnel{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return Tunnel{}, ErrInvalidDNSRequest
	}
	return getResult[Tunnel](ctx, c, http.MethodPatch, path, map[string]string{"name": name})
}

func (c *Client) DeleteTunnel(ctx context.Context, account, tunnel string) error {
	path, err := tunnelPath(account, tunnel)
	if err != nil {
		return err
	}
	_, err = getResult[struct{}](ctx, c, http.MethodDelete, path, nil)
	return err
}

type Route struct {
	ID             string `json:"id"`
	TunnelID       string `json:"tunnel_id"`
	Network        string `json:"network,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	Comment        string `json:"comment,omitempty"`
	VirtualNetwork string `json:"virtual_network_id,omitempty"`
}

type RouteInput struct {
	Value          string `json:"value"`
	Comment        string `json:"comment"`
	VirtualNetwork string `json:"virtual_network_id,omitempty"`
}

func routePath(account, tunnel, kind string) (string, error) {
	if _, err := tunnelPath(account, tunnel); err != nil {
		return "", err
	}
	switch kind {
	case "cidr":
		return "/accounts/" + account + "/teamnet/routes", nil
	case "hostname":
		return "/accounts/" + account + "/zerotrust/routes/hostname", nil
	default:
		return "", ErrInvalidDNSRequest
	}
}

func (c *Client) TunnelRoutes(ctx context.Context, account, tunnel, kind string, page int) (*DNSPage[Route], error) {
	path, err := routePath(account, tunnel, kind)
	if err != nil {
		return nil, err
	}
	return pageResult[Route](ctx, c, path, page, map[string]string{"tunnel_id": tunnel, "is_deleted": "false"})
}

func (c *Client) AddRoute(ctx context.Context, account, tunnel, kind string, in RouteInput) (Route, error) {
	path, err := routePath(account, tunnel, kind)
	if err != nil {
		return Route{}, err
	}
	body := map[string]string{"tunnel_id": tunnel}
	if utf8.RuneCountInString(in.Comment) > 100 {
		return Route{}, ErrInvalidDNSRequest
	}
	if in.Comment != "" {
		body["comment"] = in.Comment
	}
	if kind == "hostname" {
		name, err := hostName(in.Value)
		if err != nil || in.VirtualNetwork != "" {
			return Route{}, ErrInvalidDNSRequest
		}
		body["hostname"] = name
	} else {
		network, err := netip.ParsePrefix(strings.TrimSpace(in.Value))
		if err != nil || network.Masked() != network {
			return Route{}, ErrInvalidDNSRequest
		}
		body["network"] = network.String()
		if in.VirtualNetwork != "" {
			if !uuidPattern.MatchString(in.VirtualNetwork) {
				return Route{}, ErrInvalidDNSRequest
			}
			body["virtual_network_id"] = in.VirtualNetwork
		}
	}
	return getResult[Route](ctx, c, http.MethodPost, path, body)
}

func (c *Client) DeleteRoute(ctx context.Context, account, tunnel, kind, id string) error {
	path, err := routePath(account, tunnel, kind)
	if err != nil || !uuidPattern.MatchString(id) {
		return ErrInvalidDNSRequest
	}
	path += "/" + id
	row, err := getResult[Route](ctx, c, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if row.ID != id || row.TunnelID != tunnel {
		return ErrInvalidDNSRequest
	}
	_, err = getResult[struct{}](ctx, c, http.MethodDelete, path, nil)
	return err
}
