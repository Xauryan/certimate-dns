package notify

import (
	"context"
	"errors"

	"github.com/certimate-go/certimate/internal/domain"
	"github.com/pocketbase/pocketbase/core"
)

// SendStoredNotification sends an event using the live notification account's
// provider and credentials. Channel configurations never enter event metadata.
func SendStoredNotification(ctx context.Context, app core.App, accessID, subject, message string) error {
	row, err := app.FindRecordById(domain.CollectionNameAccess, accessID)
	if err != nil || row.GetString("deleted") != "" || row.GetString("reserve") != "notif" {
		return errors.New("notification account unavailable")
	}
	var config map[string]any
	if err := row.UnmarshalJSONField("config", &config); err != nil {
		return errors.New("invalid notification account configuration")
	}
	_, err = NewClient().SendNotification(ctx, &SendNotificationRequest{
		Provider: domain.NotificationProviderType(row.GetString("provider")), ProviderAccessConfig: config,
		Subject: subject, Message: message,
	})
	return err
}
