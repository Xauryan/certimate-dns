package dnsmgrextra

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testHostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestFNOSSSHDeployment(t *testing.T) {
	cert, key := extraTestPair(t)
	signer := testHostSigner(t)
	for _, tc := range []struct {
		name     string
		mismatch bool
		status   uint32
	}{
		{"verified SSH and update", false, 0},
		{"database failure", false, 14},
		{"host key mismatch", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var passwordSent atomic.Bool
			server := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
				passwordSent.Store(true)
				if string(p) != "example-password" || c.User() != "sample" {
					t.Error("invalid login credentials")
				}
				return nil, nil
			}}
			server.AddHostKey(signer)
			done := make(chan struct{})
			go func() {
				defer close(done)
				socket, err := listener.Accept()
				if err != nil {
					return
				}
				defer socket.Close()
				_ = socket.SetDeadline(time.Now().Add(5 * time.Second))
				conn, channels, global, err := ssh.NewServerConn(socket, server)
				if err != nil {
					if !tc.mismatch {
						t.Error("unexpected handshake failure")
					}
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(global)
				channel, ok := <-channels
				if !ok {
					return
				}
				if channel.ChannelType() != "session" {
					t.Error("unexpected SSH channel")
					return
				}
				r, requests, err := channel.Accept()
				if err != nil {
					t.Error(err)
					return
				}
				defer r.Close()
				request := <-requests
				if request == nil || request.Type != "exec" {
					t.Error("missing update request")
					return
				}
				var command struct{ Command string }
				if ssh.Unmarshal(request.Payload, &command) != nil || command.Command != "/usr/bin/sudo -n -- /usr/local/sbin/certimate-fnos-update" || strings.Contains(command.Command, key) || strings.Contains(command.Command, cert) {
					t.Error("unsafe SSH command")
					return
				}
				if err := request.Reply(true, nil); err != nil {
					t.Error(err)
					return
				}
				body, err := io.ReadAll(r)
				var payload fnosUpdate
				if err != nil || json.Unmarshal(body, &payload) != nil || payload.Key != key || payload.Certificate != cert {
					t.Error("invalid update over SSH stdin")
				}
				_, _ = r.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{tc.status}))
			}()
			host, port, _ := net.SplitHostPort(listener.Addr().String())
			fingerprint := ssh.FingerprintSHA256(signer.PublicKey())
			if tc.mismatch {
				fingerprint = ssh.FingerprintSHA256(testHostSigner(t).PublicKey())
			}
			provider, err := New("fnos", map[string]any{"host": host, "port": port, "username": "sample", "password": "example-password", "hostKeyFingerprint": fingerprint}, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = provider.Deploy(context.Background(), cert, key)
			<-done
			if tc.mismatch && passwordSent.Load() {
				t.Error("sent password to unverified SSH host")
			}
			if (err == nil) != (tc.status == 0 && !tc.mismatch) {
				t.Error("unexpected update result")
			}
			if tc.status == 14 && !strings.Contains(err.Error(), "database") {
				t.Error("missing failure stage")
			}
		})
	}
}
