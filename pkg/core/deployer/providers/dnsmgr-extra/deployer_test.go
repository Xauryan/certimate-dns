package dnsmgrextra

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The transport preserves production URLs and never opens a socket.
type extraTestHTTP func(*http.Request) (*http.Response, error)

func (f extraTestHTTP) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func extraTestPair(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "test issuer"}, DNSNames: []string{"node.example.test"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	raw, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}))
}

func TestKuocaiWorkflow(t *testing.T) {
	cert, key := extraTestPair(t)
	for _, tc := range []struct {
		name, login, update string
		wantCalls           int
		success             bool
	}{
		{"success", `{"code":"SUCCESS","data":"example-session"}`, `{"code":"SUCCESS"}`, 2, true},
		{"no session", `{"code":"SUCCESS"}`, "", 1, false},
		{"bad session", `{"code":"SUCCESS","data":"invalid;value"}`, "", 1, false},
		{"unsuccessful update", `{"code":"SUCCESS","data":"example-session"}`, `{"code":"FAILED","message":"example-password"}`, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := New("kuocai", map[string]any{"username": "test-account", "password": "example-password"}, map[string]any{"target": "1234567890123456789"})
			if err != nil {
				t.Fatal(err)
			}
			d := p.(*deployer)
			calls := 0
			d.client.Transport = extraTestHTTP(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Scheme != "https" || r.URL.Host != "www.kuocaicdn.com" || r.Method != "POST" || r.URL.RawQuery != "" {
					t.Fatal("invalid Kuocai URL or method")
				}
				w := httptest.NewRecorder()
				switch r.URL.Path {
				case "/login/loginUser":
					if calls != 1 || r.Header.Get("Cookie") != "" || r.PostFormValue("userAccount") != "test-account" || r.PostFormValue("userPwd") != "example-password" || r.PostFormValue("remember") != "true" {
						t.Fatal("invalid login request")
					}
					io.WriteString(w, tc.login)
				case "/CdnDomainHttps/httpsConfiguration":
					if calls != 2 || r.Header.Get("Cookie") != "kuocai_cdn_token=example-session" {
						t.Fatal("missing session")
					}
					var v struct {
						ID    string `json:"doMainId"`
						HTTPS map[string]string
					}
					if json.NewDecoder(r.Body).Decode(&v) != nil || v.ID != "1234567890123456789" || v.HTTPS["private_key"] != key || v.HTTPS["certificate_value"] != cert || v.HTTPS["certificate_source"] != "0" || v.HTTPS["https_status"] != "on" || v.HTTPS["certificate_name"] == "" {
						t.Fatal("invalid certificate update")
					}
					io.WriteString(w, tc.update)
				default:
					t.Fatal("unexpected Kuocai endpoint")
				}
				return w.Result(), nil
			})
			_, err = d.Deploy(context.Background(), cert, key)
			if (err == nil) != tc.success || calls != tc.wantCalls {
				t.Fatal("unexpected workflow result or calls")
			}
			if err != nil && strings.Contains(err.Error(), "example-password") {
				t.Fatal("leaked credential")
			}
		})
	}
}

func TestFNOSLocalFileAndDatabaseContract(t *testing.T) {
	// Exercise the exact installed Python program with a temporary catalog,
	// simulated database and service manager. All files remain in t.TempDir.
	cert, key := extraTestPair(t)
	_, otherKey := extraTestPair(t)
	fixture, err := json.Marshal(map[string]string{"certificate": cert, "key": key, "otherKey": otherKey})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/usr/bin/python3", "-I", "-c", `
import fcntl
import importlib.util
import io
import json
import os
import pathlib
import signal
import stat
import subprocess
import sys
import unittest.mock as mock

repo, directory = sys.argv[1:]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("fnos", repo)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
base = pathlib.Path(directory)
cert, key = base / "cert.pem", base / "key.pem"
old_cert = "-----BEGIN CERTIFICATE-----\nold cert\n"
old_key = "-----BEGIN PRIVATE KEY-----\nold key\n"
cert.write_text(old_cert)
key.write_text(old_key)
cert.chmod(0o644)
key.chmod(0o640)
catalog = base / "catalog.json"
row = {"certificate": str(cert), "privateKey": str(key), "san": ["node.example.test"]}
catalog.write_text(json.dumps([row]))
catalog.chmod(0o644)
module.CATALOG = catalog
fixture = json.load(sys.stdin)
other_key = fixture.pop("otherKey")
update = module.verified_update(io.BytesIO(json.dumps(fixture).encode()))
assert update["names"] == {"node.example.test"}
assert update["issuer"] == "test issuer"
assert 0 < update["notBefore"] < update["notAfter"]
# A direct helper caller cannot override targets, forge metadata, submit
# extraneous content as PEM, mismatch keys, or supply an unbounded request.
for raw in [
    json.dumps(dict(fixture, names=["another.test"])).encode(),
    json.dumps(dict(fixture, notAfter=9999999999999)).encode(),
    json.dumps(dict(fixture, certificate="arbitrary text")).encode(),
    json.dumps(dict(fixture, key=other_key)).encode(),
    json.dumps(dict(fixture, key=fixture["key"]+"malformed")).encode(),
    json.dumps(dict(fixture, certificate=fixture["certificate"]*17)).encode(),
    json.dumps(dict(fixture, certificate={})).encode(),
    b"X"*(module.MAX_INPUT+1),
    b'{"key":"one","key":"two","certificate":"malformed"}',
]:
    try:
        module.verified_update(io.BytesIO(raw))
    except (ValueError, TypeError, OSError):
        pass
    else:
        raise AssertionError("helper accepted untrusted input")
with mock.patch.object(module.time, "time", return_value=update["notAfter"]/1000+1):
    try:
        module.verified_update(io.BytesIO(json.dumps(fixture).encode()))
    except ValueError:
        pass
    else:
        raise AssertionError("expired certificate accepted")
# Temporary directories may be owned by the test user or live under /tmp.
try:
    module.check_parents(key)
except ValueError:
    pass
else:
    if str(base).startswith("/tmp/"):
        raise AssertionError("writable directory accepted")
calls = []
def record(command, **kwargs):
    calls.append(command[0])
    if command[0] == "/usr/bin/sudo":
        assert "issuer=test issuer" in command and ("key0=" + str(key)) in command
        assert b"WHERE private_key=:'key0'" in kwargs["input"]
        assert update["issuer"].encode() not in kwargs["input"]
        assert cert.read_text() == fixture["certificate"] and key.read_text() == fixture["key"]
    else:
        assert command == ["/usr/bin/systemctl", "restart", "webdav.service", "smbftpd.service", "trim_nginx.service"]
with mock.patch.object(module, "check_parents"):
    module.LOCK = str(base/"lock")
    with open(module.LOCK, "wb") as lock:
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            module.locked_install(update)
        except SystemExit as ex:
            assert ex.code == 17
        else:
            raise AssertionError("helper allowed concurrent update")
    # Loss of the SSH session during commit cannot interrupt the critical
    # section between installing the new key and updating its database row.
    events = []
    def committing(data):
        signal.raise_signal(signal.SIGTERM)
        events.append("committed")
    previous = signal.signal(signal.SIGTERM, lambda *_: events.append("terminated"))
    try:
        with mock.patch.object(module, "install", side_effect=committing):
            module.locked_install(update)
    finally:
        signal.signal(signal.SIGTERM, previous)
    assert events == ["committed", "terminated"]
    # Catalog and destination permissions are checked independently of the
    # caller's ability to generate an otherwise valid replacement pair.
    catalog.chmod(0o666)
    try:
        module.install(update)
    except SystemExit as ex:
        assert ex.code == 10
    else:
        raise AssertionError("world-writable inventory accepted")
    catalog.chmod(0o644)
    symlink = base/"linked-key.pem"
    symlink.symlink_to(key)
    catalog.write_text(json.dumps([dict(row, privateKey=str(symlink))]))
    try:
        module.install(update)
    except SystemExit as ex:
        assert ex.code == 13
    else:
        raise AssertionError("destination symlink accepted")
    assert key.read_text() == old_key
    catalog.write_text(json.dumps([row]))
    # Verify files and DB rollback if the database rejects the update.
    with mock.patch.object(module.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "psql")):
        try:
            module.install(update)
        except SystemExit as ex:
            assert ex.code == 14
        else:
            raise AssertionError("unconfirmed database update accepted")
        assert cert.read_text() == old_cert and key.read_text() == old_key
    # Refuse to lose SAN coverage and preserve unrelated certificates.
    for sans, status in [(["other.example.test"],11), (["node.example.test","other.example.test"],12)]:
        row["san"] = sans
        catalog.write_text(json.dumps([row]))
        try:
            module.install(update)
        except SystemExit as ex:
            assert ex.code == status
        else:
            raise AssertionError("invalid catalog selection")
    row["san"] = ["node.example.test"]
    catalog.write_text(json.dumps([row]))
    with mock.patch.object(module.subprocess, "run", side_effect=record):
        module.install(update)
    assert calls == ["/usr/bin/sudo", "/usr/bin/systemctl"]
    assert stat.S_IMODE(key.stat().st_mode) == 0o640
    assert not list(base.glob(".certimate-*"))
`, "fnos_update.py", t.TempDir())
	cmd.Stdin = strings.NewReader(string(fixture))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("FNOS contract: %s", output)
	}
}
