package dnscert

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/certimate-go/certimate/internal/notify"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
)

func cloneOrderNotification(tx core.App, sourceID, nextID string) error {
	_, err := tx.DB().NewQuery(`INSERT INTO dns_cert_notice_settings(order_id,access_id)
		SELECT {:next},access_id FROM dns_cert_notice_settings WHERE order_id={:source}`).
		Bind(dbx.Params{"source": sourceID, "next": nextID}).Execute()
	return err
}

func notifyOrderEvent(tx core.App, id, action, state string, success bool) error {
	// Polling an already issued certificate must not send another notice.
	key := state
	if !success {
		key = "error:" + action + ":" + state
	} else {
		switch state {
		case "issued", "revoked", "expired", "failed", "renewed", "needs_review":
		default:
			return nil
		}
	}
	_, err := tx.DB().NewQuery(`INSERT INTO dns_cert_notices(order_id,access_id,event_key,action,state,success,created)
		SELECT order_id,access_id,{:key},{:action},{:state},{:success},{:now}
		FROM dns_cert_notice_settings WHERE order_id={:id} AND access_id<>''
		ON CONFLICT(order_id,access_id,event_key) DO NOTHING`).
		Bind(dbx.Params{"id": id, "key": key, "action": action, "state": state, "success": success, "now": time.Now().Unix()}).Execute()
	return err
}

type orderNotice struct {
	ID       int    `db:"id"`
	OrderID  string `db:"order_id"`
	AccessID string `db:"access_id"`
	Action   string `db:"action"`
	State    string `db:"state"`
	Success  bool   `db:"success"`
	Attempts int    `db:"attempts"`
}

func ScheduleNotifications(app core.App) error {
	return app.Cron().Add("dns-certificate-order-notifications", "* * * * *", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
		defer cancel()
		if err := deliverOrderNotices(ctx, app, time.Now(), notify.SendStoredNotification); err != nil && ctx.Err() == nil {
			app.Logger().Warn("Could not process DNS certificate notifications")
		}
	})
}

func deliverOrderNotices(ctx context.Context, app core.App, now time.Time, send func(context.Context, core.App, string, string, string) error) error {
	const live = `EXISTS(SELECT 1 FROM dns_cert_notice_settings s JOIN dns_cert_orders o ON o.id=s.order_id AND o.state<>'deleted'
		JOIN access a ON a.id=s.access_id AND a.reserve='notif' AND a.deleted=''
		WHERE s.order_id=dns_cert_notices.order_id AND s.access_id=dns_cert_notices.access_id)`
	const due = `status IN ('pending','retrying','sending') AND next_at<={:now}`
	params := dbx.Params{"now": now.Unix()}
	// Permanently drop queued deliveries when their account is removed or replaced.
	if _, err := app.DB().NewQuery("UPDATE dns_cert_notices SET status='cancelled',lease='' WHERE " + due + " AND NOT " + live).Bind(params).WithContext(ctx).Execute(); err != nil {
		return err
	}
	var rows []orderNotice
	if err := app.DB().NewQuery("SELECT id,order_id,access_id,action,state,success,attempts FROM dns_cert_notices WHERE " + due + " AND " + live + " ORDER BY id LIMIT 20").Bind(params).WithContext(ctx).All(&rows); err != nil {
		return err
	}
	for _, n := range rows {
		lease := rand.Text()
		args := dbx.Params{"id": n.ID, "now": now.Unix(), "until": time.Now().Add(2 * time.Minute).Unix(), "lease": lease}
		result, err := app.DB().NewQuery("UPDATE dns_cert_notices SET status='sending',attempts=attempts+1,lease={:lease},next_at={:until} WHERE id={:id} AND " + due + " AND " + live).Bind(args).WithContext(ctx).Execute()
		if err != nil {
			return err
		}
		claimed, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if claimed == 0 {
			continue
		}
		outcome := "completed"
		if !n.Success || n.State == "failed" || n.State == "needs_review" {
			outcome = "requires attention"
		}
		child, cancel := context.WithTimeout(ctx, 20*time.Second)
		err = send(child, app, n.AccessID, "[Certimate] Certificate order "+outcome, fmt.Sprintf("Order %s · %s · %s", n.OrderID, n.Action, n.State))
		cancel()
		status := "accepted"
		if err != nil {
			status = "retrying"
			if n.Attempts+1 >= 5 {
				status = "failed"
			}
		}
		args["status"] = status
		args["next"] = time.Now().Add(time.Minute * time.Duration(1<<min(n.Attempts, 6))).Unix()
		if _, err := app.DB().NewQuery(`UPDATE dns_cert_notices SET status={:status},lease='',next_at={:next} WHERE id={:id} AND lease={:lease}`).Bind(args).Execute(); err != nil {
			return err
		}
	}
	return nil
}

func bindNotification(g *router.RouterGroup[*core.RequestEvent]) {
	g.GET("/orders/{id}/notification", func(e *core.RequestEvent) error {
		id := e.Request.PathValue("id")
		var accessID, status string
		err := e.App.DB().NewQuery(`SELECT coalesce(s.access_id,''),coalesce((SELECT n.status FROM dns_cert_notices n
			WHERE n.order_id=o.id AND n.access_id=s.access_id ORDER BY id DESC LIMIT 1),'')
			FROM dns_cert_orders o LEFT JOIN dns_cert_notice_settings s ON s.order_id=o.id
			WHERE o.id={:id} AND o.state<>'deleted'`).Bind(dbx.Params{"id": id}).WithContext(e.Request.Context()).Row(&accessID, &status)
		if errors.Is(err, sql.ErrNoRows) {
			err = errMissing
		}
		return reply(e, map[string]string{"accessId": accessID, "status": status}, err)
	})
	g.PUT("/orders/{id}/notification", func(e *core.RequestEvent) error {
		var input struct {
			AccessID *string `json:"accessId"`
		}
		if err := e.BindBody(&input); err != nil || input.AccessID == nil {
			return reply(e, nil, errInput)
		}
		id, accessID := e.Request.PathValue("id"), *input.AccessID
		err := e.App.RunInTransaction(func(tx core.App) error {
			args := dbx.Params{"id": id, "access": accessID}
			var exists bool
			if err := tx.DB().NewQuery(`SELECT EXISTS(SELECT 1 FROM dns_cert_orders WHERE id={:id} AND state<>'deleted') AND
				({:access}='' OR EXISTS(SELECT 1 FROM access WHERE id={:access} AND reserve='notif' AND deleted=''))`).Bind(args).Row(&exists); err != nil {
				return err
			}
			if !exists {
				return errMissing
			}
			if _, err := tx.DB().NewQuery(`INSERT INTO dns_cert_notice_settings(order_id,access_id) VALUES({:id},{:access})
				ON CONFLICT(order_id) DO UPDATE SET access_id=excluded.access_id`).Bind(args).Execute(); err != nil {
				return err
			}
			_, err := tx.DB().NewQuery(`UPDATE dns_cert_notices SET status='cancelled',lease=''
				WHERE order_id={:id} AND access_id<>{:access} AND status IN ('pending','retrying','sending')`).Bind(args).Execute()
			return err
		})
		return reply(e, map[string]string{"accessId": accessID}, err)
	})
}
