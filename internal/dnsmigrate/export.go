package dnsmigrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
)

var prefixPattern = regexp.MustCompile(`^[a-zA-Z0-9_]{0,40}$`)

// Export reads one consistent snapshot. DNSMgr's production schema uses InnoDB.
func Export(ctx context.Context, db *sql.DB, source, prefix, timezone string) (*Manifest, error) {
	if !prefixPattern.MatchString(prefix) || !identifier.MatchString(source) {
		return nil, errors.New("invalid table prefix or source namespace")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, errors.New("cannot start source read-only transaction")
	}
	defer tx.Rollback()
	m := &Manifest{Version: Version, Source: source, Timezone: timezone, Accounts: []Account{}, Zones: []Zone{}, Tasks: []Task{}}
	if err := tx.QueryRowContext(ctx, "SELECT `value` FROM `"+prefix+"config` WHERE `key`='version'").Scan(&m.Schema); err != nil || m.Schema != 1049 {
		return nil, errors.New("expected DNSMgr MySQL schema 1049")
	}
	read := func(table, columns string, scan func(*sql.Rows) error) error {
		rows, err := tx.QueryContext(ctx, "SELECT "+columns+" FROM `"+prefix+table+"` ORDER BY id")
		if err != nil {
			return fmt.Errorf("could not read source table %s", table)
		}
		defer rows.Close()
		for rows.Next() {
			if err := scan(rows); err != nil {
				return fmt.Errorf("invalid source row in %s", table)
			}
		}
		if rows.Err() != nil {
			return fmt.Errorf("incomplete snapshot of %s", table)
		}
		return nil
	}
	if err = read("account", "id,type", func(r *sql.Rows) error {
		var a Account
		if err := r.Scan(&a.ID, &a.Provider); err != nil {
			return err
		}
		m.Accounts = append(m.Accounts, a)
		return nil
	}); err != nil {
		return nil, err
	}
	if err = read("domain", "id,aid,cid,name,COALESCE(thirdid,''),COALESCE(SUBSTR(expiretime,1,10),''),is_notice,COALESCE(SUBSTR(regtime,1,10),''),is_hide,is_sso", func(r *sql.Rows) error {
		var z Zone
		if err := r.Scan(&z.ID, &z.AccountID, &z.CategoryID, &z.Name, &z.ProviderID, &z.Expires, &z.Notice, &z.Registered, &z.Hidden, &z.QuickLogin); err != nil {
			return err
		}
		m.Zones = append(m.Zones, z)
		return nil
	}); err != nil {
		return nil, err
	}
	if err = read("sctask", "id,did,rr,recordid,active,type,cycle,switchtype,COALESCE(switchdate,''),COALESCE(switchtime,''),COALESCE(value,''),COALESCE(line,'')", func(r *sql.Rows) error {
		s := new(Schedule)
		t := Task{Kind: "sctask", Schedule: s}
		if err := r.Scan(&t.ID, &t.ZoneID, &t.RR, &t.Record, &t.Active, &s.Mode, &s.Cycle, &s.Action, &s.Day, &s.At, &s.Value, &s.ProxyLine); err != nil {
			return err
		}
		m.Tasks = append(m.Tasks, t)
		return nil
	}); err != nil {
		return nil, err
	}
	if err = read("dmtask", "id,did,rr,recordid,active,type,COALESCE(main_value,''),COALESCE(backup_value,''),checktype,COALESCE(checkurl,'') <> '',COALESCE(tcpport,0),frequency,cycle,timeout,proxy,cdn", func(r *sql.Rows) error {
		f := new(Monitor)
		t := Task{Kind: "dmtask", Monitor: f}
		if err := r.Scan(&t.ID, &t.ZoneID, &t.RR, &t.Record, &t.Active, &f.Action, &f.Primary, &f.Backup, &f.Protocol, &f.HasURL, &f.Port, &f.Frequency, &f.Cycles, &f.Timeout, &f.Proxy, &f.CDN); err != nil {
			return err
		}
		m.Tasks = append(m.Tasks, t)
		return nil
	}); err != nil {
		return nil, err
	}
	if err = read("optimizeip", "id,did,rr,active,type,ip_type,cdn_type,recordnum,ttl", func(r *sql.Rows) error {
		o := new(Optimize)
		t := Task{Kind: "optimizeip", Optimize: o}
		if err := r.Scan(&t.ID, &t.ZoneID, &t.RR, &t.Active, &o.Mode, &o.Family, &o.CDN, &o.Count, &o.TTL); err != nil {
			return err
		}
		m.Tasks = append(m.Tasks, t)
		return nil
	}); err != nil {
		return nil, err
	}
	accountProviders := make(map[int64]string, len(m.Accounts))
	zoneProviders := make(map[int64]string, len(m.Zones))
	for _, a := range m.Accounts {
		accountProviders[a.ID] = a.Provider
	}
	for _, z := range m.Zones {
		zoneProviders[z.ID] = accountProviders[z.AccountID]
	}
	for n := range m.Tasks {
		t := &m.Tasks[n]
		if !hasStableRecordID(zoneProviders[t.ZoneID]) {
			t.Record = ""
		}
	}
	if err := m.readRelated(read); err != nil {
		return nil, err
	}
	m.History = &HistoryCounts{}
	for _, count := range []struct {
		table string
		total *int64
	}{
		{"config", &m.History.Configuration}, {"log", &m.History.Operations}, {"dmlog", &m.History.Monitor},
	} {
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+prefix+count.table+"`").Scan(count.total); err != nil {
			return nil, fmt.Errorf("could not count source table %s", count.table)
		}
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if tx.Commit() != nil {
		return nil, errors.New("source snapshot commit failed")
	}
	return m, nil
}
