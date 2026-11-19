package dnscatalog

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/notify"
)

type deliver func(context.Context, *Domain) error

const reminderKey = "z.expiresOn || '/' || cast(z.reminderDays AS integer) || '/' || z.notificationRef"

const pending = dueClause + ` AND z.notificationRef<>'' AND z.reminderClaimUntil<={:now}
 AND z.reminderSentFor<>(` + reminderKey + `) AND EXISTS
 (SELECT 1 FROM access channel WHERE channel.id=z.notificationRef AND channel.deleted='' AND channel.reserve='notif')`

// RunReminders claims each delivery individually so overlapping scheduler
// invocations don't send the same reminder. A crashed worker's claim expires.
func runReminders(ctx context.Context, app core.App, now time.Time, send deliver) error {
	p := dbx.Params{"today": now.UTC().Format(time.DateOnly), "now": now.Unix()}
	var ids []string
	err := app.DB().NewQuery("SELECT z.id" + fromZones + pending + " ORDER BY z.reminderClaimUntil,z.expiresOn,z.id LIMIT 128").Bind(p).WithContext(ctx).Column(&ids)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		token := rand.Text()
		p["id"] = id
		p["token"] = token
		p["until"] = now.Add(10 * time.Minute).Unix()
		var z *Domain
		err = app.RunInTransaction(func(tx core.App) error {
			claimed, err := tx.DB().NewQuery(`UPDATE dnsZone SET reminderClaim={:token},reminderClaimUntil={:until}
			WHERE id={:id} AND id IN (SELECT z.id` + fromZones + pending + " AND z.id={:id})").Bind(p).WithContext(ctx).Execute()
			if err != nil {
				return err
			}
			n, err := claimed.RowsAffected()
			if err != nil || n == 0 {
				return err
			}
			z, err = Lookup(tx, id)
			return err
		})
		if err != nil {
			return err
		}
		if z == nil {
			continue
		}
		sendCtx, cancel := context.WithTimeout(ctx, time.Minute)
		sendErr := send(sendCtx, z)
		cancel()
		update := "reminderClaim='', reminderClaimUntil={:retry}"
		args := dbx.Params{"id": id, "token": token, "retry": now.Add(time.Hour).Unix()}
		if sendErr == nil {
			update = "reminderClaim='', reminderClaimUntil=0, reminderSentFor={:key}"
			args["key"] = fmt.Sprintf("%s/%d/%s", z.ExpiresOn, z.ReminderDays, z.NotificationID)
			delete(args, "retry")
		} else {
			app.Logger().Warn("DNS expiry reminder delivery failed", "domainId", id)
		}
		if _, err = app.DB().NewQuery("UPDATE dnsZone SET " + update + " WHERE id={:id} AND reminderClaim={:token}").Bind(args).Execute(); err != nil {
			return err
		}
	}
	return nil
}

func ScheduleReminders(app core.App) error {
	if err := scheduleRegistrationRefresh(app); err != nil {
		return err
	}
	return app.Cron().Add("dns-domain-expiry-reminders", "7 * * * *", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		err := runReminders(ctx, app, time.Now(), func(ctx context.Context, z *Domain) error {
			return notify.SendStoredNotification(ctx, app, z.NotificationID, "[Certimate] DNS domain expiry reminder", fmt.Sprintf("%s expires on %s (UTC).", z.Name, z.ExpiresOn))
		})
		if err != nil {
			app.Logger().Error("DNS expiry reminder check failed")
		}
	})
}
