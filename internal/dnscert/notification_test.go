package dnscert

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

func TestOrderNotificationOutbox(t *testing.T) {
	app := newChallengeFixture(t).app
	col, err := app.FindCollectionByNameOrId("access")
	if err != nil {
		t.Fatal(err)
	}
	channel := core.NewRecord(col)
	channel.Set("name", "test notification")
	channel.Set("provider", "sendcloud")
	channel.Set("reserve", "notif")
	channel.Set("config", map[string]string{"apiKey": "synthetic-private"})
	if err := app.Save(channel); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB().Insert("dns_cert_notice_settings", dbx.Params{"order_id": "one", "access_id": channel.Id}).Execute(); err != nil {
		t.Fatal(err)
	}
	if err := app.RunInTransaction(func(tx core.App) error {
		if err := notifyOrderEvent(tx, "one", "refresh", "failed", false); err != nil {
			t.Fatal(err)
		}
		return errors.New("rollback certificate state transition")
	}); err == nil {
		t.Fatal("expected rollback")
	}
	for range 2 {
		if err := notifyOrderEvent(app, "one", "refresh", "issued", true); err != nil {
			t.Fatal(err)
		}
	}
	if err := cloneOrderNotification(app, "one", "two"); err != nil {
		t.Fatal(err)
	}
	if err := notifyOrderEvent(app, "two", "renewal", "needs_review", false); err != nil {
		t.Fatal(err)
	}
	var total int
	if err := app.DB().NewQuery("SELECT count(*) FROM dns_cert_notices").Row(&total); err != nil || total != 2 {
		t.Fatal("incorrect notice count", total, err)
	}
	if _, err := app.DB().NewQuery("UPDATE dns_cert_notice_settings SET access_id='' WHERE order_id='two'").Execute(); err != nil {
		t.Fatal(err)
	}
	calls := 0
	send := func(ctx context.Context, app core.App, id, subject, message string) error {
		calls++
		if id != channel.Id || !strings.Contains(message, "one") || strings.Contains(subject+message, "synthetic-private") {
			t.Fatal("unexpected event metadata or target")
		}
		if calls == 1 {
			return errors.New("temporary delivery failure")
		}
		return nil
	}
	now := time.Now()
	for _, at := range []time.Time{now, now.Add(-time.Second), now.Add(2 * time.Minute), now.Add(3 * time.Minute)} {
		if err := deliverOrderNotices(t.Context(), app, at, send); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatalf("expected one retry; got %d deliveries", calls)
	}
	for id, want := range map[string]string{"one": "accepted", "two": "cancelled"} {
		var actual string
		if err := app.DB().NewQuery("SELECT status FROM dns_cert_notices WHERE order_id={:id}").Bind(dbx.Params{"id": id}).Row(&actual); err != nil || actual != want {
			t.Fatal(id, actual, err)
		}
	}
}
