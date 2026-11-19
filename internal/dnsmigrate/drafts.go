package dnsmigrate

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/certimate-go/certimate/internal/dnsautomation"
)

func recordType(value string) string {
	if ip, err := netip.ParseAddr(value); err == nil {
		if ip.Is4() {
			return "A"
		}
		return "AAAA"
	}
	if value != "" && address(value) {
		return "CNAME"
	}
	return ""
}

func draft(t Task, zone Zone, account, providerZone, timezone string) (*dnsautomation.Definition, string) {
	name := zone.Name
	if t.RR != "@" {
		name = t.RR + "." + name
	}
	d := dnsautomation.Definition{Name: fmt.Sprintf("DNSMgr %s %d", t.Kind, t.ID), Target: dnsautomation.Target{AccountID: account, ZoneID: providerZone, RecordID: t.Record, Name: name}}
	switch t.Kind {
	case "optimizeip":
		return nil, "review candidate source, ranks, target lines and address families"
	case "sctask":
		s := t.Schedule
		if s.Action != 0 || s.ProxyLine != "" {
			return nil, "verify original record type and status/proxy change"
		}
		d.Kind = "schedule"
		d.Action = "update"
		d.Value = s.Value
		d.Target.Type = recordType(s.Value)
		if s.Mode == 0 {
			loc, _ := time.LoadLocation(timezone)
			at, err := time.ParseInLocation("2006-01-02T15:04", strings.Replace(s.At, " ", "T", 1), loc)
			if err != nil {
				return nil, "review single-run time"
			}
			d.Schedule = dnsautomation.Schedule{Cycle: "once", At: at.Format(time.RFC3339)}
		} else if s.Mode == 1 && s.Cycle >= 0 && s.Cycle <= 2 {
			cycles := []string{"daily", "weekly", "monthly"}
			d.Schedule = dnsautomation.Schedule{Cycle: cycles[s.Cycle], At: s.At, Timezone: timezone}
			if s.Cycle != 0 {
				day, err := strconv.Atoi(s.Day)
				if err != nil {
					return nil, "review recurrence day"
				}
				d.Schedule.Day = day
			}
		} else {
			return nil, "unsupported recurrence"
		}
	case "dmtask":
		f := t.Monitor
		if f.Proxy || f.CDN || f.HasURL {
			return nil, "review legacy endpoint or proxy settings"
		}
		if f.Protocol != 1 || (f.Action != 1 && f.Action != 2) {
			return nil, "review legacy probe and switch mode"
		}
		d.Kind = "failover"
		d.Action = "disable"
		d.Primary = f.Primary
		d.Target.Type = recordType(f.Primary)
		if f.Action == 2 {
			d.Action = "replace"
			d.Backup = f.Backup
		}
		d.Monitor = dnsautomation.Monitor{Protocol: "tcp", Port: f.Port, Interval: f.Frequency, Timeout: f.Timeout, FailureThreshold: f.Cycles, RecoveryThreshold: f.Cycles}
	default:
		return nil, "unknown task kind"
	}
	if d.Validate() != nil {
		return nil, "review parameters outside native automation limits"
	}
	return &d, ""
}
