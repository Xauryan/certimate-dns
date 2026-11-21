package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/core"

	_ "github.com/certimate-go/certimate/migrations"
)

func TestDDNSNodeCreateWritesPrivateToken(t *testing.T) {
	dir := t.TempDir()
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: filepath.Join(dir, "data")})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.ResetBootstrapState() })
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}

	create := func(name, path string) (string, error) {
		t.Helper()
		command := NewDDNSNodeCommand(app)
		var output bytes.Buffer
		command.SetOut(&output)
		command.SetErr(&output)
		command.SilenceErrors = true
		command.SetArgs([]string{"create", "--name", name, "--token-file", path})
		err := command.Execute()
		return strings.TrimSpace(output.String()), err
	}

	path := filepath.Join(dir, "node-token")
	id, err := create("vm-test", path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode is %v", info.Mode())
	}
	token, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(bytes.TrimSpace(token))
	var node struct {
		ID   string `db:"id"`
		Hash string `db:"token_hash"`
	}
	if err := app.DB().Select("id", "token_hash").From("ddns_nodes").One(&node); err != nil {
		t.Fatal(err)
	}
	if node.ID != id || node.Hash != hex.EncodeToString(digest[:]) {
		t.Fatal("command output and token file do not match the persisted identity")
	}
	if _, err := create("vm-second", path); !errors.Is(err, os.ErrExist) {
		t.Fatal("existing token file was not rejected")
	}
	if reread, err := os.ReadFile(path); err != nil || !bytes.Equal(reread, token) {
		t.Fatal("existing token file was changed")
	}
	badPath := filepath.Join(dir, "bad-token")
	if _, err := create(" bad name", badPath); err == nil {
		t.Fatal("invalid node name was accepted")
	}
	if _, err := os.Stat(badPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed enrollment left a token file")
	}
	var count int
	if err := app.DB().Select("COUNT(*)").From("ddns_nodes").Row(&count); err != nil || count != 1 {
		t.Fatal("failed enrollment created an additional node")
	}
}
