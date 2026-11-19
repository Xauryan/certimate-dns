package dnsidentity

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/certimate-go/certimate/internal/dnsauth"
)

// NewResetCommand recovers a member without a live HTTP session.
func NewResetCommand(app core.App) *cobra.Command {
	return newResetCommand("dns-member-reset", "DNS member", "member", func(email string, password []byte) error {
		return resetMember(app, email, password)
	})
}

// NewAdminResetCommand restores administrator access using local server access.
func NewAdminResetCommand(app core.App) *cobra.Command {
	cmd := newResetCommand("dns-admin-reset", "administrator", "administrator", func(email string, password []byte) error {
		return resetAdmin(app, email, password)
	})
	cmd.AddCommand(&cobra.Command{
		Use: "unlock", Args: cobra.NoArgs, Short: "Clear administrator password login failures",
		RunE: func(_ *cobra.Command, _ []string) error {
			_, err := app.DB().Delete("dns_login_attempts", dbx.HashExp{"scope": adminAttemptScope}).Execute()
			return err
		},
	})
	return cmd
}

func newResetCommand(name, account, prompt string, reset func(string, []byte) error) *cobra.Command {
	cmd := &cobra.Command{Use: name, Short: "Recover a " + account + " account"}
	cmd.AddCommand(&cobra.Command{Use: "totp EMAIL", Args: cobra.ExactArgs(1), Short: "Remove the authenticator and revoke sessions",
		RunE: func(_ *cobra.Command, args []string) error { return reset(args[0], nil) }})
	cmd.AddCommand(&cobra.Command{Use: "password EMAIL", Aliases: []string{"pwd"}, Args: cobra.ExactArgs(1), Short: "Read a new password from standard input and revoke sessions",
		RunE: func(command *cobra.Command, args []string) error {
			var password []byte
			var err error
			input := command.InOrStdin()
			if f, ok := input.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
				fmt.Fprintf(command.ErrOrStderr(), "New %s password: ", prompt)
				password, err = term.ReadPassword(int(f.Fd()))
				fmt.Fprintln(command.ErrOrStderr())
			} else {
				password, err = io.ReadAll(io.LimitReader(input, 75))
				password = bytes.TrimSuffix(bytes.TrimSuffix(password, []byte("\n")), []byte("\r"))
			}
			defer clear(password)
			if err != nil {
				return err
			}
			if bytes.ContainsAny(password, "\r\n") || len(password) < 10 || len(password) > 72 {
				return errors.New("password must contain 10 to 72 bytes on one line")
			}
			return reset(args[0], password)
		}})
	return cmd
}

func resetAdmin(app core.App, email string, password []byte) error {
	return app.RunInTransaction(func(tx core.App) error {
		admin, err := tx.FindAuthRecordByEmail(core.CollectionNameSuperusers, email)
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("administrator not found")
		}
		if err != nil {
			return err
		}
		if password == nil {
			if _, err := tx.DB().Delete("dns_admin_totp", dbx.HashExp{"admin": admin.Id}).Execute(); err != nil {
				return err
			}
		} else {
			admin.SetPassword(string(password))
		}
		return revokeAdminSessions(tx, admin)
	})
}

func resetMember(app core.App, email string, password []byte) error {
	return app.RunInTransaction(func(tx core.App) error {
		member, err := tx.FindAuthRecordByEmail(dnsauth.Members, email)
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("member not found")
		}
		if err != nil {
			return err
		}
		if password == nil {
			if _, err := tx.DB().Delete("dns_member_totp", dbx.HashExp{"member": member.Id}).Execute(); err != nil {
				return err
			}
		} else {
			// Discard pending enrollment from before the password reset. An
			// enrolled authenticator continues to protect the recovered account.
			if _, err := tx.DB().Delete("dns_member_totp", dbx.HashExp{"member": member.Id, "active": false}).Execute(); err != nil {
				return err
			}
			member.SetPassword(string(password))
		}
		return revokeAuthSessions(tx, member)
	})
}
