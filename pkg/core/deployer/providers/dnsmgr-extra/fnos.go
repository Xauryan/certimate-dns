package dnsmgrextra

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// The SSH user is authorized to invoke this preinstalled helper without arguments.
const fnosUpdateCommand = "/usr/bin/sudo -n -- /usr/local/sbin/certimate-fnos-update"

type fnosUpdate struct {
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
}

func (d *deployer) deployFNOS(ctx context.Context, leaf *x509.Certificate, cert, key string) error {
	if len(leaf.DNSNames)+len(leaf.IPAddresses) == 0 {
		return errors.New("FNOS requires a certificate with DNS or IP subject alternative names")
	}
	update, err := json.Marshal(fnosUpdate{Certificate: cert, Key: key})
	if err != nil {
		return errors.New("could not encode FNOS update")
	}
	cfg := &ssh.ClientConfig{
		User: d.username, Auth: []ssh.AuthMethod{ssh.Password(d.password)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != d.fingerprint {
				return errors.New("FNOS SSH host key mismatch")
			}
			return nil
		},
	}
	opCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(opCtx, "tcp", d.sshAddress)
	if err != nil {
		return errors.New("FNOS SSH endpoint unavailable")
	}
	defer conn.Close()
	stop := context.AfterFunc(opCtx, func() { _ = conn.Close() })
	defer stop()
	c, ch, rq, err := ssh.NewClientConn(conn, d.sshAddress, cfg)
	if err != nil {
		return errors.New("FNOS SSH host verification or authentication failed")
	}
	client := ssh.NewClient(c, ch, rq)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return errors.New("FNOS SSH session unavailable")
	}
	defer session.Close()
	session.Stdin = bytes.NewReader(update)
	if err := session.Run(fnosUpdateCommand); err != nil {
		if opCtx.Err() != nil {
			return opCtx.Err()
		}
		var e *ssh.ExitError
		if errors.As(err, &e) {
			switch e.ExitStatus() {
			case 10:
				return errors.New("FNOS certificate catalog is unavailable or invalid")
			case 11:
				return errors.New("FNOS has no matching certificate entries")
			case 12:
				return errors.New("replacement certificate does not cover all names on a matching FNOS entry")
			case 13:
				return errors.New("FNOS certificate files could not be staged")
			case 14:
				return errors.New("FNOS file or database update failed; verify remote certificate state")
			case 16:
				return errors.New("FNOS helper rejected the certificate, private key or input")
			case 17:
				return errors.New("FNOS helper lock unavailable; check active deployments and retry")
			case 15:
				return errors.New("FNOS certificate updated but service restart failed")
			}
		}
		return errors.New("FNOS did not confirm the update; check the installed certificate helper, its sudo rule and remote certificate state")
	}
	return nil
}
