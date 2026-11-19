// Package dnsproxysettings stores the optional proxy used by DNS management accounts.
package dnsproxysettings

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/security"
	"golang.org/x/net/idna"
)

var (
	errInvalid = errors.New("invalid DNS proxy settings")
	errRead    = errors.New("could not read DNS proxy settings")
	errWrite   = errors.New("could not save DNS proxy settings")
)

type row struct {
	Enabled     bool   `db:"enabled"`
	Server      string `db:"server"`
	Credentials string `db:"credentials"`
}

type auth struct{ Username, Password string }

type input struct {
	Enabled  *bool   `json:"enabled"`
	Server   *string `json:"server"`
	Username *string `json:"username"`
	Password *string `json:"password"`
}

type view struct {
	Enabled     bool   `json:"enabled"`
	Configured  bool   `json:"configured"`
	Server      string `json:"server"`
	Scheme      string `json:"scheme"`
	HasUsername bool   `json:"hasUsername"`
	HasPassword bool   `json:"hasPassword"`
}

func read(app core.App) (row, error) {
	var r row
	if err := app.DB().NewQuery(`SELECT enabled,server,credentials FROM dns_proxy_settings WHERE id=1`).One(&r); err != nil {
		return row{}, errRead
	}
	return r, nil
}

func parseServer(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 1024 || u.Opaque != "" || u.User != nil || u.Hostname() == "" || u.Path != "" && u.Path != "/" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") {
		return nil, errInvalid
	}
	switch u.Scheme {
	case "http", "https", "socks4", "socks5", "socks5h":
	default:
		return nil, errInvalid
	}
	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.String()
	} else {
		host, err = idna.Lookup.ToASCII(host)
		if err != nil || len(host) > 253 {
			return nil, errInvalid
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 {
				return nil, errInvalid
			}
		}
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errInvalid
	}
	return &url.URL{Scheme: u.Scheme, Host: net.JoinHostPort(host, strconv.Itoa(port))}, nil
}

// Keep the key in the application data directory so a normal full backup restores it.
// Publish a completed 0600 file atomically, including across concurrent first saves.
func encryptionKey(app core.App, create bool) (string, error) {
	path := filepath.Join(app.DataDir(), ".dns-proxy.key")
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && create {
		f, err := os.CreateTemp(app.DataDir(), ".dns-proxy-key-*")
		if err != nil {
			return "", errWrite
		}
		defer os.Remove(f.Name())
		b := make([]byte, 32)
		_, e := rand.Read(b)
		if e == nil {
			_, e = f.Write(b)
		}
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			return "", errWrite
		}
		if err = os.Link(f.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
			return "", errWrite
		}
		key, err = os.ReadFile(path)
		if err != nil {
			return "", errRead
		}
	} else if err != nil {
		return "", errRead
	}
	if len(key) != 32 {
		return "", errRead
	}
	return string(key), nil
}

func (r row) auth(app core.App) (auth, error) {
	if r.Credentials == "" {
		return auth{}, nil
	}
	key, err := encryptionKey(app, false)
	if err != nil {
		return auth{}, err
	}
	// Reject truncated ciphertext before calling the PocketBase nonce decoder.
	sealed, err := base64.StdEncoding.DecodeString(r.Credentials)
	if err != nil || len(sealed) < 12+16 {
		return auth{}, errRead
	}
	data, err := security.Decrypt(r.Credentials, key)
	if err != nil {
		return auth{}, errRead
	}
	var a auth
	if err := json.Unmarshal(data, &a); err != nil {
		return auth{}, errRead
	}
	return a, nil
}

func (r row) proxyURL(app core.App) (*url.URL, error) {
	if r.Server == "" {
		return nil, nil
	}
	u, err := parseServer(r.Server)
	if err != nil {
		return nil, errRead
	}
	a, err := r.auth(app)
	if err != nil {
		return nil, err
	}
	if a.Password != "" {
		u.User = url.UserPassword(a.Username, a.Password)
	} else if a.Username != "" {
		u.User = url.User(a.Username)
	}
	return u, nil
}

// LoadURL returns nil when the global proxy is disabled. The URL may contain credentials.
func LoadURL(app core.App) (*url.URL, error) {
	r, err := read(app)
	if err != nil {
		return nil, err
	}
	if !r.Enabled {
		return nil, nil
	}
	if r.Server == "" {
		return nil, errRead
	}
	return r.proxyURL(app)
}

func settingsView(app core.App) (view, error) {
	r, err := read(app)
	if err != nil {
		return view{}, err
	}
	v := view{Enabled: r.Enabled}
	if r.Server == "" {
		return v, nil
	}
	u, err := parseServer(r.Server)
	if err != nil {
		return v, errRead
	}
	a, err := r.auth(app)
	if err != nil {
		return v, err
	}
	v.Configured = true
	v.Scheme = u.Scheme
	v.Server = u.String()
	v.HasUsername = a.Username != ""
	v.HasPassword = a.Password != ""
	return v, nil
}

func save(app core.App, in input) error {
	if in.Enabled == nil {
		return errInvalid
	}
	return app.RunInTransaction(func(tx core.App) error {
		r, err := read(tx)
		if err != nil {
			return err
		}
		if in.Server != nil {
			server := ""
			if *in.Server != "" {
				u, err := parseServer(*in.Server)
				if err != nil {
					return err
				}
				server = u.String()
			}
			// Never send the old credentials to a replacement endpoint.
			if server != r.Server {
				r.Credentials = ""
			}
			r.Server = server
		}
		if *in.Enabled && r.Server == "" {
			return errInvalid
		}
		if in.Username != nil || in.Password != nil {
			var a auth
			// Specifying the complete credential pair also recovers a replacement instance key.
			if in.Username == nil || in.Password == nil {
				a, err = r.auth(tx)
				if err != nil {
					return err
				}
			}
			if in.Username != nil {
				a.Username = *in.Username
			}
			if in.Password != nil {
				a.Password = *in.Password
			}
			if len(a.Username) > 255 || len(a.Password) > 255 || strings.IndexFunc(a.Username, unicode.IsControl) >= 0 || strings.IndexFunc(a.Password, unicode.IsControl) >= 0 || (a.Password != "" && a.Username == "") {
				return errInvalid
			}
			r.Credentials = ""
			if a.Username != "" {
				if r.Server == "" || strings.HasPrefix(r.Server, "socks4://") && a.Password != "" {
					return errInvalid
				}
				key, err := encryptionKey(tx, true)
				if err != nil {
					return err
				}
				b, err := json.Marshal(a)
				if err != nil {
					return errWrite
				}
				r.Credentials, err = security.Encrypt(b, key)
				if err != nil {
					return errWrite
				}
			}
		}
		_, err = tx.DB().NewQuery(`UPDATE dns_proxy_settings SET enabled={:enabled},server={:server},credentials={:credentials} WHERE id=1`).Bind(dbx.Params{"enabled": *in.Enabled, "server": r.Server, "credentials": r.Credentials}).Execute()
		if err != nil {
			return errWrite
		}
		return nil
	})
}
