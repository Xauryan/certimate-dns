//go:build windows && (amd64 || arm64)

// The Windows helper accepts one fixed certificate operation over stdin.
package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/certimate-go/certimate/internal/iisbind"
	"golang.org/x/sys/windows"
)

const basePath = `C:\Windows\System32\certimate-iis-bind`

func main() {
	// Exit codes summarize stages; stdout/stderr never contain request material.
	if len(os.Args) != 1 {
		os.Exit(10)
	}
	req, err := iisbind.Read(os.Stdin)
	if err != nil {
		os.Exit(10)
	}
	pair, err := req.Validate(time.Now())
	if err != nil {
		os.Exit(10)
	}
	if err = install(req.Target, pair); err != nil {
		os.Exit(11)
	}
	_, _ = io.WriteString(os.Stdout, iisbind.Confirmation(pair.Leaf))
}

func install(target string, pair tls.Certificate) error {
	// Serialize helpers across SSH sessions, including after a client disconnect.
	lockPath, _ := windows.UTF16PtrFromString(basePath + ".lock")
	lock, err := windows.CreateFile(lockPath, windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(lock)
	policy, err := os.Open(basePath + ".targets")
	if err != nil {
		return err
	}
	defer policy.Close()
	data, err := io.ReadAll(io.LimitReader(policy, 65537))
	if err != nil || len(data) > 65536 {
		return errors.New("invalid binding policy")
	}
	create, err := iisbind.Authorize(string(data), target)
	if err != nil {
		return err
	}
	host, port, err := iisbind.Target(target)
	if err != nil {
		return err
	}
	// HttpUpdateServiceConfiguration updates an existing binding atomically.
	if err = updateConfig.Find(); err != nil {
		return err
	}
	status, _, _ := initializeHTTP.Call(2, 2, 0)
	if status != 0 {
		return windows.Errno(status)
	}
	defer terminateHTTP.Call(2, 0)
	key, err := bindingKey(host, port)
	if err != nil {
		return err
	}
	current, err := lookup(key)
	if err != nil {
		return err
	}
	if current == nil && !create {
		return errors.New("selected binding is absent")
	}
	storeName := "MY"
	if current != nil && current.record.Param.StoreName != nil {
		storeName = windows.UTF16PtrToString(current.record.Param.StoreName)
		if !strings.EqualFold(storeName, "MY") && !strings.EqualFold(storeName, "WebHosting") {
			return errors.New("unsupported certificate store")
		}
	}
	// HTTP.sys identifies certificate bindings by their SHA-1 thumbprint.
	hash := sha1.Sum(pair.Leaf.Raw)
	if err := storeCertificate(storeName, pair, hash[:]); err != nil {
		return err
	}
	// Read again immediately before updating to retain current flags and avoid
	// recreating an entry another administrator removed during the import.
	latest, err := lookup(key)
	if err != nil {
		return err
	}
	if latest == nil && current != nil || latest != nil && current == nil {
		return errors.New("binding changed during certificate import")
	}
	if latest != nil {
		if !latest.samePolicyAndHash(current) {
			return errors.New("binding changed during certificate import")
		}
		if bytes.Equal(latest.hash(), hash[:]) {
			return nil
		}
	}
	if err = apply(key, latest, hash[:]); err != nil {
		return err
	}
	confirmed, err := lookup(key)
	if err != nil {
		return err
	}
	if confirmed == nil || !bytes.Equal(confirmed.hash(), hash[:]) {
		return errors.New("binding update was not confirmed")
	}
	return nil
}
