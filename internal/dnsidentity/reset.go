package dnsidentity

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"golang.org/x/term"
	"io"
	"os"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/spf13/cobra"

	"github.com/certimate-go/certimate/internal/dnsauth"
)

// NewResetCommand recovers a member without a live HTTP session.
func NewResetCommand(app core.App) *cobra.Command {
	cmd := &cobra.Command{Use: "dns-member-reset", Short: "Recover a DNS member account"}
	cmd.AddCommand(&cobra.Command{Use: "totp EMAIL", Args: cobra.ExactArgs(1), Short: "Remove the authenticator and revoke member sessions",
		RunE: func(_ *cobra.Command, args []string) error { return resetMember(app, args[0], nil) }})
	cmd.AddCommand(&cobra.Command{Use: "password EMAIL", Aliases: []string{"pwd"}, Args: cobra.ExactArgs(1), Short: "Read a new password from standard input and revoke member sessions",
		RunE: func(command *cobra.Command, args []string) error {
			var password []byte
			var err error
			input := command.InOrStdin()
			if f, ok := input.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
				fmt.Fprint(command.ErrOrStderr(), "New member password: ")
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
			return resetMember(app, args[0], password)
		}})
	return cmd
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
		return rotateMember(tx, member)
	})
}
