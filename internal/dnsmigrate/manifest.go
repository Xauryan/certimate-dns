// Package dnsmigrate transfers DNSMgr inventory without transferring credentials.
package dnsmigrate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

const Version = 1
const MaxFileSize = 64 << 20

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var dnsLabel = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)
var providerKey = regexp.MustCompile(`^[a-z][a-z0-9]{0,24}$`)
var zoneIdentifier = regexp.MustCompile(`^[A-Za-z0-9_.:|-]{1,128}$`)
var cfID = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
var recordID = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

// Manifest has no general-purpose metadata or credential fields. All task
// parameters are typed or selected from known DNS fields. In particular,
// check URLs, free-form remarks, credentials, and record snapshots stay out.
type Manifest struct {
	Version  int            `json:"version"`
	Source   string         `json:"source"`
	Schema   int            `json:"dnsMgrSchema"`
	Timezone string         `json:"timezone"`
	Accounts []Account      `json:"accounts"`
	Zones    []Zone         `json:"zones"`
	Tasks    []Task         `json:"tasks"`
	Related  []Related      `json:"related,omitempty"`
	History  *HistoryCounts `json:"historyCounts,omitempty"`
}
type Account struct {
	ID       int64  `json:"id"`
	Provider string `json:"provider"`
}
type Zone struct {
	Registered string `json:"registeredOn,omitempty"`
	Hidden     bool   `json:"hidden,omitempty"`
	QuickLogin bool   `json:"hadQuickLogin,omitempty"`
	ID         int64  `json:"id"`
	AccountID  int64  `json:"accountId"`
	Name       string `json:"name"`
	ProviderID string `json:"providerZoneId,omitempty"`
	Expires    string `json:"expiresOn,omitempty"`
	Notice     bool   `json:"hadExpiryNotice,omitempty"`
	CategoryID int64  `json:"categoryId,omitempty"`
}
type Task struct {
	ID       int64     `json:"id"`
	ZoneID   int64     `json:"zoneId"`
	Kind     string    `json:"kind"`
	RR       string    `json:"rr"`
	Record   string    `json:"recordId,omitempty"`
	Active   bool      `json:"wasActive"`
	Schedule *Schedule `json:"schedule,omitempty"`
	Monitor  *Monitor  `json:"monitor,omitempty"`
	Optimize *Optimize `json:"optimize,omitempty"`
}
type Schedule struct {
	Mode      int    `json:"mode"`
	Cycle     int    `json:"cycle"`
	Action    int    `json:"action"`
	Day       string `json:"day,omitempty"`
	At        string `json:"at"`
	Value     string `json:"value,omitempty"`
	ProxyLine string `json:"proxyLine,omitempty"`
}
type Monitor struct {
	Action    int    `json:"action"`
	Primary   string `json:"primary"`
	Backup    string `json:"backup,omitempty"`
	Protocol  int    `json:"protocol"`
	HasURL    bool   `json:"hadCheckUrl,omitempty"`
	Port      int    `json:"port,omitempty"`
	Frequency int    `json:"frequency"`
	Cycles    int    `json:"cycles"`
	Timeout   int    `json:"timeout"`
	Proxy     bool   `json:"proxy,omitempty"`
	CDN       bool   `json:"cdn,omitempty"`
}
type Optimize struct {
	Mode   int    `json:"mode"`
	Family string `json:"family"`
	CDN    int    `json:"cdn"`
	Count  int    `json:"count"`
	TTL    int    `json:"ttl"`
}
type Bindings struct {
	Promotions []Promotion      `json:"promotions,omitempty"`
	Version    int              `json:"version"`
	Source     string           `json:"source"`
	Accounts   map[int64]string `json:"accounts"`
}

func (b Bindings) Validate(m *Manifest) error {
	if b.Version != Version || b.Source != m.Source {
		return errors.New("binding version or source namespace does not match manifest")
	}
	accounts := make(map[int64]bool, len(m.Accounts))
	for _, a := range m.Accounts {
		accounts[a.ID] = true
	}
	for id := range b.Accounts {
		if !accounts[id] {
			return fmt.Errorf("binding references unknown account %d", id)
		}
	}
	return b.validatePromotions()
}

func Decode(r io.Reader, dst any) error {
	data, err := io.ReadAll(io.LimitReader(r, MaxFileSize+1))
	if err != nil || len(data) > MaxFileSize {
		return errors.New("unreadable or oversized input")
	}
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid or unsupported JSON fields")
	}
	return nil
}
func canonicalName(s string, relative bool) (string, error) {
	if relative && s == "@" {
		return s, nil
	}
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	labels := strings.Split(s, ".")
	for i, label := range labels {
		if relative && i == 0 && label == "*" {
			continue
		}
		if !dnsLabel.MatchString(label) {
			a, e := idna.Lookup.ToASCII(label)
			if e != nil || !dnsLabel.MatchString(a) {
				return "", errors.New("invalid DNS name")
			}
			labels[i] = a
		}
		if !relative && strings.Contains(labels[i], "_") {
			return "", errors.New("invalid zone name")
		}
	}
	name := strings.Join(labels, ".")
	if len(name) > 253 || name == "" {
		return "", errors.New("invalid DNS name length")
	}
	return name, nil
}
func address(s string) bool {
	if s == "" {
		return true
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	_, err := canonicalName(s, false)
	return err == nil && strings.Contains(s, ".")
}
func (m *Manifest) Validate() error {
	if m.Version != Version || m.Schema != 1049 || !identifier.MatchString(m.Source) {
		return errors.New("unsupported manifest, source namespace, or DNSMgr schema")
	}
	if _, err := time.LoadLocation(m.Timezone); err != nil || m.Timezone == "" || m.Timezone == "Local" {
		return errors.New("invalid source timezone")
	}
	accounts := map[int64]string{}
	zones := map[int64]bool{}
	keys := map[string]bool{}
	for _, a := range m.Accounts {
		if a.ID <= 0 || accounts[a.ID] != "" || !providerKey.MatchString(a.Provider) {
			return fmt.Errorf("invalid or duplicate account %d", a.ID)
		}
		accounts[a.ID] = a.Provider
	}
	for i := range m.Zones {
		z := &m.Zones[i]
		name, err := canonicalName(z.Name, false)
		if err != nil || z.ID <= 0 || zones[z.ID] || accounts[z.AccountID] == "" || (z.ProviderID != "" && !zoneIdentifier.MatchString(z.ProviderID)) {
			return fmt.Errorf("invalid, duplicate, or orphan zone %d", z.ID)
		}
		for _, date := range []string{z.Registered, z.Expires} {
			if date != "" {
				if _, err := time.Parse(time.DateOnly, date); err != nil {
					return fmt.Errorf("invalid registration date for zone %d", z.ID)
				}
			}
		}
		z.Name = name
		zones[z.ID] = true
	}
	for i := range m.Tasks {
		t := &m.Tasks[i]
		rr, err := canonicalName(t.RR, true)
		key := fmt.Sprintf("%s/%d", t.Kind, t.ID)
		if t.ID <= 0 || keys[key] || !zones[t.ZoneID] || err != nil || (t.Record != "" && !recordID.MatchString(t.Record)) {
			return fmt.Errorf("invalid, duplicate, or orphan task %d", t.ID)
		}
		keys[key] = true
		t.RR = rr
		valid := false
		switch t.Kind {
		case "sctask":
			s := t.Schedule
			valid = s != nil && t.Monitor == nil && t.Optimize == nil && address(s.Value) && (s.ProxyLine == "" || s.ProxyLine == "0" || s.ProxyLine == "1") && (s.Day == "" || datePart.MatchString(s.Day)) && (s.At == "" || clockText.MatchString(s.At))
		case "dmtask":
			f := t.Monitor
			valid = f != nil && t.Schedule == nil && t.Optimize == nil && address(f.Primary) && address(f.Backup)
		case "optimizeip":
			o := t.Optimize
			valid = o != nil && t.Schedule == nil && t.Monitor == nil && (o.Family == "v4" || o.Family == "v6" || o.Family == "v4,v6" || o.Family == "v6,v4")
		}
		if !valid {
			return fmt.Errorf("invalid task configuration %d", t.ID)
		}
	}
	return m.validateRelated(zones)
}

var datePart = regexp.MustCompile(`^[0-9]{1,2}$`)
var clockText = regexp.MustCompile(`^[0-9T: -]{4,19}$`)

func hash(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func targetID(source, kind string, id int64) string { return hash([]any{source, kind, id})[:15] }
