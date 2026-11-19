package iis

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/certimate-go/certimate/internal/iisbind"
	"golang.org/x/crypto/ssh"
)

func TestDeployUsesOnlyPinnedSSHSubsystem(t *testing.T) {
	const target = "site.example.test:8443"
	cert, key, receipt := fixtureCertificate(t)
	for _, scenario := range []string{"success", "wrong-host-key", "invalid-target", "refused", "incorrect-receipt", "failed-exit"} {
		t.Run(scenario, func(t *testing.T) {
			srv, fingerprint, request := helperFixture(t, scenario, receipt)
			wantTarget := target
			switch scenario {
			case "wrong-host-key":
				fingerprint = "SHA256:" + strings.Repeat("A", 43)
			case "invalid-target":
				wantTarget = "other.example.test"
			}
			host := srv.Addr().(*net.TCPAddr)
			d, err := New(map[string]any{"host": host.IP.String(), "port": host.Port, "username": "fixture", "password": "fixture-password", "hostKeyFingerprint": fingerprint},
				map[string]any{"target": wantTarget})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			_, err = d.Deploy(ctx, cert, key)
			if (err == nil) != (scenario == "success") || err != nil && (strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), "fixture-password")) {
				t.Fatalf("unexpected or unsafe result: %v", err)
			}
			switch scenario {
			case "wrong-host-key", "invalid-target", "refused":
				select {
				case <-request:
					t.Fatal("certificate was sent before authenticated subsystem acceptance")
				default:
				}
			default:
				select {
				case req := <-request:
					if req.Target != target || req.Certificate != cert || req.PrivateKey != key {
						t.Fatal("unexpected helper request")
					}
				default:
					t.Fatal("expected helper request")
				}
			}
		})
	}
}

func fixtureCertificate(t *testing.T) (string, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"site.example.test"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), iisbind.Confirmation(leaf)
}

func helperFixture(t *testing.T, scenario, receipt string) (net.Listener, string, <-chan iisbind.Request) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if c.User() != "fixture" || string(password) != "fixture-password" {
			return nil, errors.New("invalid credentials")
		}
		return nil, nil
	}}
	config.AddHostKey(hostKey)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan iisbind.Request, 1)
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		server, channels, requests, err := ssh.NewServerConn(conn, config)
		if err != nil {
			if scenario != "wrong-host-key" {
				t.Error("fixture could not authenticate client")
			}
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		newChannel := <-channels
		if newChannel == nil || newChannel.ChannelType() != "session" || len(newChannel.ExtraData()) != 0 {
			t.Error("unexpected SSH channel")
			return
		}
		channel, incoming, err := newChannel.Accept()
		if err != nil {
			return
		}
		defer channel.Close()
		first := <-incoming
		var subsystem struct{ Name string }
		if first == nil || first.Type != "subsystem" || ssh.Unmarshal(first.Payload, &subsystem) != nil || subsystem.Name != iisbind.Subsystem {
			t.Error("client requested something other than the IIS subsystem")
			return
		}
		if scenario == "refused" {
			_ = first.Reply(false, nil)
			return
		}
		_ = first.Reply(true, nil)
		req, err := iisbind.Read(channel)
		if err != nil {
			t.Error("fixture could not decode IIS binding")
			return
		}
		received <- req
		output := receipt
		if scenario == "incorrect-receipt" {
			output += "upstream diagnostic"
		}
		_, _ = io.WriteString(channel, output)
		var status [4]byte
		if scenario == "failed-exit" {
			binary.BigEndian.PutUint32(status[:], 11)
		}
		_, _ = channel.SendRequest("exit-status", false, status[:])
	}()
	return listener, ssh.FingerprintSHA256(hostKey.PublicKey()), received
}
