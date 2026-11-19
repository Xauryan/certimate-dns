// Package dnsproxy builds isolated outgoing transports for DNS management accounts.
package dnsproxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	xhttp "github.com/certimate-go/certimate/pkg/utils/http"
	"golang.org/x/net/proxy"
)

var errConfig = errors.New("invalid DNS proxy settings")
var errConnect = errors.New("DNS proxy connection failed")

// NewTransport configures a route independently of process-wide proxy environment
// variables. A nil URL means an explicitly direct connection.
func NewTransport(u *url.URL) (*http.Transport, error) {
	tr := xhttp.NewDefaultTransport()
	tr.Proxy = nil
	if u == nil {
		return tr, nil
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || u.Hostname() == "" || u.Opaque != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errConfig
	}
	endpoint := *u // Callers may replace their settings on the next request.
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	switch endpoint.Scheme {
	case "http", "https":
		tr.Proxy = http.ProxyURL(&endpoint)
		if endpoint.Scheme == "https" {
			// Some self-hosted DNS accounts allow a private origin certificate.
			// Authenticate the proxy independently, including for those accounts.
			secure := &tls.Dialer{NetDialer: dialer, Config: &tls.Config{ServerName: endpoint.Hostname(), MinVersion: tls.VersionTLS12}}
			tr.DialTLSContext = secure.DialContext
		}
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if endpoint.User != nil {
			name := endpoint.User.Username()
			password, _ := endpoint.User.Password()
			if len(name) > 255 || len(password) > 255 {
				return nil, errConfig
			}
			auth = &proxy.Auth{User: name, Password: password}
		}
		d, err := proxy.SOCKS5("tcp", endpoint.Host, auth, dialer)
		if err != nil {
			return nil, errConfig
		}
		connect := d.(proxy.ContextDialer)
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if endpoint.Scheme == "socks5" {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, errConnect
				}
				ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
				if err != nil || len(ips) == 0 {
					return nil, errConnect
				}
				addr = net.JoinHostPort(ips[0].IP.String(), port)
			}
			conn, err := connect.DialContext(ctx, network, addr)
			if err != nil {
				return nil, errConnect
			}
			return conn, nil
		}
	case "socks4":
		user := ""
		if endpoint.User != nil {
			user = endpoint.User.Username()
		}
		if strings.ContainsRune(user, 0) || len(user) > 255 {
			return nil, errConfig
		}
		tr.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialSOCKS4(ctx, dialer, endpoint.Host, addr, user)
		}
	default:
		return nil, errConfig
	}
	return tr, nil
}

func dialSOCKS4(ctx context.Context, dialer *net.Dialer, server, destination, username string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		return nil, errConnect
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return nil, errConnect
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 || ips[0].To4() == nil {
		return nil, errConnect
	}
	conn, err := dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, errConnect
	}
	// Interrupt a stalled SOCKS handshake when the request is cancelled.
	cancel := context.AfterFunc(ctx, func() { conn.Close() })
	defer cancel()
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
	request := []byte{4, 1, 0, 0}
	binary.BigEndian.PutUint16(request[2:], uint16(n))
	request = append(request, ips[0].To4()...)
	request = append(request, username...)
	request = append(request, 0)
	var reply [8]byte
	if _, err = conn.Write(request); err == nil {
		_, err = io.ReadFull(conn, reply[:])
	}
	if err != nil || reply[0] != 0 || reply[1] != 90 {
		conn.Close()
		return nil, errConnect
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}
