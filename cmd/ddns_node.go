package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/pocketbase/pocketbase/core"
	"github.com/spf13/cobra"

	"github.com/certimate-go/certimate/internal/ddnsfleet"
)

// NewDDNSNodeCommand manages DDNS enrollment from the Certimate server console.
func NewDDNSNodeCommand(app core.App) *cobra.Command {
	group := &cobra.Command{
		Use:          "ddns-node",
		Short:        "Manage DDNS reporting nodes from the local server",
		SilenceUsage: true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if app.IsBootstrapped() {
				return nil
			}
			return app.Bootstrap()
		},
	}
	var name, tokenPath string
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a reporting node and save its one-time token in a new private file",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			id, err := writeDDNSNodeToken(app, name, tokenPath)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(command.OutOrStdout(), id)
			return err
		},
	}
	create.Flags().StringVar(&name, "name", "", "Node display name")
	create.Flags().StringVar(&tokenPath, "token-file", "", "New file in an operator-only directory, outside backups")
	_ = create.MarkFlagRequired("name")
	_ = create.MarkFlagRequired("token-file")
	group.AddCommand(create)
	registerDDNSBindingCommands(group, app)
	registerDDNSAccessCommands(group, app)
	return group
}

func writeDDNSNodeToken(app core.App, name, tokenPath string) (string, error) {
	file, err := os.OpenFile(tokenPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create node token file: %w", err)
	}
	defer file.Close()

	var id string
	err = app.RunInTransaction(func(tx core.App) error {
		node, err := ddnsfleet.EnrollNode(tx, name)
		if err != nil {
			return err
		}
		if _, err := file.WriteString(node.Token + "\n"); err != nil {
			return fmt.Errorf("write node token file: %w", err)
		}
		if err := file.Sync(); err != nil {
			return fmt.Errorf("sync node token file: %w", err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close node token file: %w", err)
		}
		id = node.ID
		return nil
	})
	if err != nil {
		// Close before removal so failed enrollments can be cleaned up on Windows too.
		_ = file.Close()
		return "", errors.Join(err, os.Remove(tokenPath))
	}
	return id, nil
}
