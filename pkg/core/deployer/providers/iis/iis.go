// Package iis rotates a single host:port SNI binding via a preinstalled
// Windows SSH subsystem that takes all certificate material on stdin.
package iis

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/certimate-go/certimate/internal/iisbind"
	"github.com/certimate-go/certimate/pkg/core"
	"github.com/certimate-go/certimate/pkg/utils/cert/hostname"
	"golang.org/x/crypto/ssh"
)

type deployer struct {
	address, target string
	config          ssh.ClientConfig
}

func New(access, fields map[string]any) (core.Deployer, error) {
	get := func(key string) string { s, _ := access[key].(string); return s }
	host, username, password, fingerprint := get("host"), get("username"), get("password"), get("hostKeyFingerprint")
	if (!hostname.IsDNSName(host) && net.ParseIP(host) == nil) || strings.TrimSpace(username) == "" || password == "" {
		return nil, errors.New("invalid Windows SSH account")
	}
	digest, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(fingerprint, "SHA256:"))
	if err != nil || len(digest) != 32 || fingerprint != "SHA256:"+base64.RawStdEncoding.EncodeToString(digest) {
		return nil, errors.New("a pinned SSH SHA256 host fingerprint is required")
	}
	port := 22
	if v, ok := access["port"]; ok && v != nil && v != "" {
		port, err = strconv.Atoi(fmt.Sprint(v))
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("invalid SSH port")
		}
	}
	target, _ := fields["target"].(string)
	if _, _, err = iisbind.Target(target); err != nil {
		return nil, err
	}
	return &deployer{address: net.JoinHostPort(host, strconv.Itoa(port)), target: target, config: ssh.ClientConfig{
		User: username, Auth: []ssh.AuthMethod{ssh.Password(password)}, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if subtle.ConstantTimeCompare([]byte(ssh.FingerprintSHA256(key)), []byte(fingerprint)) != 1 {
				return errors.New("Windows SSH host key mismatch")
			}
			return nil
		},
	}}, nil
}
func (*deployer) SetLogger(*slog.Logger) {}

func (d *deployer) Deploy(ctx context.Context, certificate, key string) (*core.DeployerDeployResult, error) {
	req := iisbind.Request{Target: d.target, Certificate: certificate, PrivateKey: key}
	pair, err := req.Validate(time.Now())
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(req)
	if err != nil || len(body) > iisbind.MaxRequest {
		return nil, errors.New("IIS certificate request is too large")
	}
	defer clear(body)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, errors.New("Windows SSH endpoint unavailable")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	c, channels, requests, err := ssh.NewClientConn(conn, d.address, &d.config)
	if err != nil {
		return nil, errors.New("Windows SSH authentication or host verification failed")
	}
	client := ssh.NewClient(c, channels, requests)
	defer client.Close()
	channel, incoming, err := client.OpenChannel("session", nil)
	if err != nil {
		return nil, errors.New("Windows SSH session unavailable")
	}
	defer channel.Close()
	expected := iisbind.Confirmation(pair.Leaf)
	if err := runHelper(channel, incoming, body, expected); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return &core.DeployerDeployResult{}, nil
}

func runHelper(ch ssh.Channel, incoming <-chan *ssh.Request, body []byte, expected string) error {
	exit := make(chan bool, 1)
	go func() {
		reports, succeeded := 0, false
		for msg := range incoming {
			if msg.Type == "exit-status" {
				reports++
				succeeded = len(msg.Payload) == 4 && binary.BigEndian.Uint32(msg.Payload) == 0
			}
			_ = msg.Reply(false, nil)
		}
		exit <- reports == 1 && succeeded
	}()
	go func() { _, _ = io.Copy(io.Discard, ch.Stderr()) }()

	started, err := ch.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{iisbind.Subsystem}))
	if err != nil || !started {
		return errors.New("Windows SSH certificate subsystem unavailable")
	}
	unconfirmed := errors.New("Windows did not confirm the IIS certificate binding; inspect the selected target before retrying")
	if _, err := io.Copy(ch, bytes.NewReader(body)); err != nil || ch.CloseWrite() != nil {
		return unconfirmed
	}
	receipt, err := io.ReadAll(io.LimitReader(ch, int64(len(expected)+1)))
	if err != nil || string(receipt) != expected || !<-exit {
		return unconfirmed
	}
	return nil
}
