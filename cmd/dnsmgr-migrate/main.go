// dnsmgr-migrate transfers a DNSMgr inventory into an existing Certimate data directory.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"time"
	_ "time/tzdata"

	"github.com/certimate-go/certimate/internal/dnsmigrate"
	"github.com/go-sql-driver/mysql"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: dnsmgr-migrate export|dry-run|import [flags]")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	if args[0] == "export" {
		source := fs.String("source", "", "stable identifier of the source installation")
		prefix := fs.String("prefix", "dnsmgr_", "DNSMgr MySQL table prefix")
		zone := fs.String("timezone", "Asia/Shanghai", "source PHP timezone")
		path := fs.String("out", "", "new manifest path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || *path == "" || *source == "" {
			return errors.New("export requires -source and -out")
		}
		dsn := os.Getenv("DNSMGR_MYSQL_DSN")
		if dsn == "" {
			return errors.New("set DNSMGR_MYSQL_DSN for the read-only source")
		}
		cfg, err := mysql.ParseDSN(dsn)
		if err != nil {
			return errors.New("invalid source DSN")
		}
		cfg.MultiStatements = false
		cfg.Timeout = 15 * time.Second
		cfg.ReadTimeout = time.Minute
		cfg.Logger = log.New(io.Discard, "", 0)
		con, err := mysql.NewConnector(cfg)
		if err != nil {
			return errors.New("invalid source connection settings")
		}
		db := sql.OpenDB(con)
		defer db.Close()
		m, err := dnsmigrate.Export(ctx, db, *source, *prefix, *zone)
		if err != nil {
			return err
		}
		return publish(*path, m)
	}
	if args[0] != "dry-run" && args[0] != "import" {
		return errors.New("unknown command; expected export, dry-run, or import")
	}
	dir := fs.String("dir", "", "existing migrated Certimate data directory")
	path := fs.String("in", "", "manifest path")
	bindings := fs.String("bindings", "", "account bindings JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *dir == "" || *path == "" || *bindings == "" {
		return errors.New("specify -dir, -in, and -bindings")
	}
	var m dnsmigrate.Manifest
	var b dnsmigrate.Bindings
	if err := read(*path, &m); err != nil {
		return err
	}
	if err := read(*bindings, &b); err != nil {
		return err
	}
	if err := m.Validate(); err != nil {
		return err
	}
	if err := b.Validate(&m); err != nil {
		return err
	}
	data, err := filepath.Abs(filepath.Join(*dir, "data.db"))
	if err != nil {
		return errors.New("invalid data directory")
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(data), RawQuery: "mode=ro"}
	db, err := dbx.Open("sqlite", u.String())
	if err != nil {
		return errors.New("cannot open destination")
	}
	defer db.Close()
	var report *dnsmigrate.Report
	err = db.TransactionalContext(ctx, &sql.TxOptions{ReadOnly: true}, func(tx *dbx.Tx) error { var e error; report, e = dnsmigrate.Plan(ctx, tx, &m, b); return e })
	if err != nil {
		return errors.New("cannot plan import; check that the destination data directory exists and all DNS migrations have run")
	}
	if args[0] == "import" && report.Conflicts == 0 {
		app := core.NewBaseApp(core.BaseAppConfig{DataDir: *dir})
		if app.Bootstrap() != nil {
			return errors.New("could not bootstrap destination")
		}
		defer app.ResetBootstrapState()
		report, err = dnsmigrate.Apply(ctx, app, &m, b)
		if err != nil && !errors.Is(err, dnsmigrate.ErrConflict) {
			return errors.New("database import failed; no inventory changes committed")
		}
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return err
	}
	if report.Conflicts != 0 {
		return dnsmigrate.ErrConflict
	}
	return nil
}
func read(path string, out any) error {
	f, err := os.Open(path)
	if err != nil {
		return errors.New("could not open input file")
	}
	defer f.Close()
	return dnsmigrate.Decode(f, out)
}
func publish(path string, m *dnsmigrate.Manifest) error {
	// Write privately, then publish in one link operation. A retry cannot replace
	// a prior export, and interrupted writes cannot leave a partial manifest there.
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil || len(data)+1 > dnsmigrate.MaxFileSize {
		return errors.New("manifest exceeds file size limit")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".dnsmgr-export-*")
	if err != nil {
		return errors.New("cannot create private output")
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return errors.New("cannot write manifest")
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Link(f.Name(), path); err != nil {
		return errors.New("output path exists or cannot publish manifest")
	}
	return nil
}
