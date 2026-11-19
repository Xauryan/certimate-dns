package dnsautomation

import (
	"context"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"time"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

type Target struct {
	AccountID string `json:"accountId"`
	ZoneID    string `json:"zoneId"`
	RecordID  string `json:"recordId"`
	Name      string `json:"name"`
	Type      string `json:"type"`
}

type Schedule struct {
	Proxied  *bool  `json:"proxied,omitempty"`
	Cycle    string `json:"cycle"`
	At       string `json:"at"`
	Day      int    `json:"day,omitempty"`
	Timezone string `json:"timezone,omitempty"`
}

type Monitor struct {
	Origin            string `json:"origin,omitempty"`
	Protocol          string `json:"protocol"`
	Port              int    `json:"port"`
	Interval          int    `json:"interval"`
	Timeout           int    `json:"timeout"`
	FailureThreshold  int    `json:"failureThreshold"`
	RecoveryThreshold int    `json:"recoveryThreshold"`
	Cooldown          int    `json:"cooldown"`
	HealthyLimit      int    `json:"healthyLimit,omitempty"`
}

type Definition struct {
	BackupProxied  bool     `json:"backupProxied,omitempty"`
	Name           string   `json:"name"`
	Kind           string   `json:"kind"`
	Target         Target   `json:"target"`
	Action         string   `json:"action"`
	Value          string   `json:"value,omitempty"`
	Primary        string   `json:"primary,omitempty"`
	Backup         string   `json:"backup,omitempty"`
	Schedule       Schedule `json:"schedule,omitempty"`
	Monitor        Monitor  `json:"monitor,omitempty"`
	NotifyAccessID string   `json:"notifyAccessId,omitempty"`
}

type Task struct {
	ID         string     `json:"id" db:"id"`
	Definition Definition `json:"definition" db:"-"`
	Config     string     `json:"-" db:"config"`
	State      string     `json:"state" db:"state"`
	Position   string     `json:"position" db:"position"`
	Failures   int        `json:"failures" db:"failures"`
	Recoveries int        `json:"recoveries" db:"recoveries"`
	SwitchAt   int64      `json:"switchAt" db:"switch_at"`
	NextAt     int64      `json:"nextAt" db:"next_at"`
	LastAt     int64      `json:"lastAt" db:"last_at"`
	Lease      string     `json:"-" db:"lease"`
	LeaseEnd   int64      `json:"-" db:"lease_end"`
	Version    int        `json:"version" db:"version"`
}

type Run struct {
	ID       string `json:"id" db:"id"`
	TaskID   string `json:"taskId" db:"task_id"`
	Actor    string `json:"actor" db:"actor"`
	Action   string `json:"action" db:"action"`
	Outcome  string `json:"outcome" db:"outcome"`
	Started  int64  `json:"started" db:"started"`
	Finished int64  `json:"finished" db:"finished"`
	// Snapshots are exposed only to the authenticated task administrator.
	Before       string `json:"before,omitempty" db:"before_record"`
	After        string `json:"after,omitempty" db:"after_record"`
	Notification string `json:"notification,omitempty" db:"notification"`
}
type Event struct {
	TaskID   string
	RunID    string
	AccessID string
	Action   string
	Outcome  string
}
type Resolver func(context.Context, Target) (dns.Provider, error)
type Notifier func(context.Context, Event) error

var (
	ErrNoNotification = errors.New("no DNS notification channel configured")
	errInput          = errors.New("invalid automation definition or action")
	errConflict       = errors.New("automation changed, is running, or needs review")
	errProvider       = errors.New("DNS target unavailable or provider capability missing")
	errMissing        = errors.New("DNS record not found")
	errIdentity       = errors.New("DNS record identity or value changed")
	labelRE           = regexp.MustCompile(`^[a-zA-Z0-9](?:[-a-zA-Z0-9]{0,61}[a-zA-Z0-9])?$`)
)

func fqdn(name string) bool {
	s := strings.TrimSuffix(name, ".")
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, v := range strings.Split(s, ".") {
		if !labelRE.MatchString(v) {
			return false
		}
	}
	return true
}

func addressValue(kind, value string) bool {
	if kind == "CNAME" {
		return fqdn(value)
	}
	ip, err := netip.ParseAddr(value)
	return err == nil && ip.Zone() == "" && ((kind == "A" && ip.Is4()) || (kind == "AAAA" && ip.Is6() && !ip.Is4In6()))
}

func (d Definition) probeOrigin() string {
	if d.Target.Type == "CNAME" {
		return d.Monitor.Origin
	}
	return d.Primary
}

func (d Definition) validate(now time.Time) error {
	t := d.Target
	if strings.TrimSpace(d.Name) == "" || len(d.Name) > 128 || !fqdn(strings.TrimPrefix(t.Name, "*.")) || (t.Type != "A" && t.Type != "AAAA" && t.Type != "CNAME") {
		return errInput
	}
	for _, id := range []string{t.AccountID, t.ZoneID, t.RecordID} {
		if strings.TrimSpace(id) == "" || len(id) > 255 || strings.ContainsAny(id, "/\\\r\n\x00") {
			return errInput
		}
	}
	if len(d.NotifyAccessID) > 128 {
		return errInput
	}
	if d.BackupProxied && (d.Kind != "failover" || d.Action != "replace") || d.Schedule.Proxied != nil && (d.Kind != "schedule" || d.Action != "update") {
		return errInput
	}
	switch d.Kind {
	case "schedule":
		if d.Action != "update" && d.Action != "enable" && d.Action != "disable" && d.Action != "delete" {
			return errInput
		}
		if d.Action == "update" && !addressValue(t.Type, d.Value) {
			return errInput
		}
		if d.Action == "delete" && d.Schedule.Cycle != "once" {
			return errInput
		}
		_, err := d.Schedule.next(now)
		return err
	case "failover":
		m := d.Monitor
		if m.Interval < 5 || m.Interval > 86400 || m.Cooldown < 0 || m.Cooldown > 604800 || m.FailureThreshold < 1 || m.FailureThreshold > 100 || m.RecoveryThreshold < 1 || m.RecoveryThreshold > 100 {
			return errInput
		}
		if d.Action == "standby" {
			if m.HealthyLimit < 0 || m.HealthyLimit > 100 {
				return errInput
			}
			return nil
		}
		if d.Action != "replace" && d.Action != "disable" && d.Action != "observe" {
			return errInput
		}
		if !addressValue(t.Type, d.Primary) || !allowedProbeIP(d.probeOrigin()) || !fqdn(t.Name) {
			return errInput
		}
		if d.Monitor.Origin != "" && t.Type != "CNAME" {
			return errInput
		}
		if d.Action == "replace" && (!addressValue(t.Type, d.Backup) || sameValue(t.Type, d.Primary, d.Backup)) {
			return errInput
		}
		if m.Timeout < 1 || m.Timeout > 15 || m.Timeout > m.Interval || !validProtocol(m) {
			return errInput
		}
		return nil
	}
	return errInput
}

// Recurring schedules use a wall clock in the configured IANA zone. Skip missing
// dates (e.g. February 31) and DST gaps; run once on a repeated local date.
func (s Schedule) next(now time.Time) (time.Time, error) {
	if s.Cycle == "once" {
		t, err := time.Parse(time.RFC3339, s.At)
		if err != nil {
			return time.Time{}, errInput
		}
		return t, nil
	}
	if s.Cycle != "daily" && s.Cycle != "weekly" && s.Cycle != "monthly" {
		return time.Time{}, errInput
	}
	if (s.Cycle == "weekly" && (s.Day < 0 || s.Day > 6)) || (s.Cycle == "monthly" && (s.Day < 1 || s.Day > 31)) {
		return time.Time{}, errInput
	}
	if s.Timezone == "" || s.Timezone == "Local" {
		return time.Time{}, errInput
	}
	loc, err := time.LoadLocation(s.Timezone)
	if err != nil {
		return time.Time{}, errInput
	}
	clock, err := time.Parse("15:04", s.At)
	if err != nil || clock.Format("15:04") != s.At {
		return time.Time{}, errInput
	}
	n := now.In(loc)
	date := time.Date(n.Year(), n.Month(), n.Day(), 12, 0, 0, 0, loc)
	for i := 0; i < 370; i++ {
		at := time.Date(date.Year(), date.Month(), date.Day(), clock.Hour(), clock.Minute(), 0, 0, loc)
		if at.After(now) && at.Hour() == clock.Hour() && at.Minute() == clock.Minute() && (s.Cycle != "weekly" || int(at.Weekday()) == s.Day) && (s.Cycle != "monthly" || at.Day() == s.Day) {
			return at, nil
		}
		date = date.AddDate(0, 0, 1)
	}
	return time.Time{}, errInput
}
