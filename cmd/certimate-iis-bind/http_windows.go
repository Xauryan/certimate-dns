//go:build windows && (amd64 || arm64)

package main

import (
	"bytes"
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Structures mirror the 64-bit Windows SDK HTTP_SERVICE_CONFIG_SSL_SNI_* ABI.
type sniKey struct {
	Address [128]byte // SOCKADDR_STORAGE: wildcard IPv4 address, network-order port
	Host    *uint16
}
type sniQuery struct {
	Mode  uint32
	Key   sniKey
	Token uint32
}
type sslParam struct {
	HashLength                                           uint32
	Hash                                                 *byte
	AppID                                                windows.GUID
	StoreName                                            *uint16
	CheckMode, RevocationFreshness, RevocationURLTimeout uint32
	CtlName, CtlStore                                    *uint16
	Flags                                                uint32
}
type sniRecord struct {
	Key   sniKey
	Param sslParam
}
type binding struct {
	record sniRecord
	buffer []byte // Windows returns pointers into this buffer.
}

const sniConfig = 5 // HttpServiceConfigSslSniCertInfo
var (
	httpAPI        = windows.NewLazySystemDLL("httpapi.dll")
	initializeHTTP = httpAPI.NewProc("HttpInitialize")
	terminateHTTP  = httpAPI.NewProc("HttpTerminate")
	queryConfig    = httpAPI.NewProc("HttpQueryServiceConfiguration")
	setConfig      = httpAPI.NewProc("HttpSetServiceConfiguration")
	updateConfig   = httpAPI.NewProc("HttpUpdateServiceConfiguration")
)

func bindingKey(host string, port uint16) (sniKey, error) {
	var key sniKey
	key.Address[0] = windows.AF_INET
	key.Address[2] = byte(port >> 8)
	key.Address[3] = byte(port)
	name, err := windows.UTF16PtrFromString(host)
	key.Host = name
	return key, err
}

func lookup(key sniKey) (*binding, error) {
	q := sniQuery{Key: key}
	var size uint32
	call := func(out *byte, length uint32) windows.Errno {
		status, _, _ := queryConfig.Call(0, sniConfig, uintptr(unsafe.Pointer(&q)), unsafe.Sizeof(q), uintptr(unsafe.Pointer(out)), uintptr(length), uintptr(unsafe.Pointer(&size)), 0)
		runtime.KeepAlive(q)
		return windows.Errno(status)
	}
	rc := call(nil, 0)
	if rc == windows.ERROR_FILE_NOT_FOUND {
		return nil, nil
	}
	if rc != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, errors.New("SNI binding query rejected")
	}
	if size < uint32(unsafe.Sizeof(sniRecord{})) || size > 1<<20 {
		return nil, errors.New("invalid SNI binding size")
	}
	out := make([]byte, size)
	rc = call(&out[0], size)
	if rc != 0 {
		return nil, rc
	}
	b := &binding{record: *(*sniRecord)(unsafe.Pointer(&out[0])), buffer: out}
	if b.record.Param.Hash == nil || b.record.Param.HashLength != 20 {
		return nil, errors.New("invalid TLS binding hash")
	}
	return b, nil
}

func (b *binding) hash() []byte { return unsafe.Slice(b.record.Param.Hash, b.record.Param.HashLength) }
func (b *binding) samePolicyAndHash(other *binding) bool {
	a, c := b.record.Param, other.record.Param
	return bytes.Equal(b.hash(), other.hash()) && a.AppID == c.AppID && a.CheckMode == c.CheckMode && a.Flags == c.Flags && a.RevocationFreshness == c.RevocationFreshness && a.RevocationURLTimeout == c.RevocationURLTimeout && windows.UTF16PtrToString(a.StoreName) == windows.UTF16PtrToString(c.StoreName) && windows.UTF16PtrToString(a.CtlName) == windows.UTF16PtrToString(c.CtlName) && windows.UTF16PtrToString(a.CtlStore) == windows.UTF16PtrToString(c.CtlStore)
}

func apply(key sniKey, previous *binding, hash []byte) error {
	record := sniRecord{Key: key}
	call := setConfig
	if previous != nil {
		record.Param = previous.record.Param
		call = updateConfig
	} else {
		record.Param.StoreName, _ = windows.UTF16PtrFromString("MY")
		record.Param.AppID = windows.GUID{Data1: 0x1b76bf1a, Data2: 0xaf9f, Data3: 0x4628, Data4: [8]byte{0xb6, 0x3d, 0x53, 0x8d, 0x44, 0xc6, 0x56, 0x67}}
	}
	record.Param.HashLength = uint32(len(hash))
	record.Param.Hash = &hash[0]
	status, _, _ := call.Call(0, sniConfig, uintptr(unsafe.Pointer(&record)), unsafe.Sizeof(record), 0)
	runtime.KeepAlive(previous)
	runtime.KeepAlive(record)
	if status != 0 {
		return windows.Errno(status)
	}
	return nil
}
