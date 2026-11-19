package dnsidentity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
)

const qqAPI = "https://api.bot.qq.com"

var qqClient = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
var errQQ = errors.New("QQ notification delivery failed")
var eventLabel = regexp.MustCompile(`^[a-zA-Z0-9_:-]{1,128}$`)
var validationToken = regexp.MustCompile(`^[a-zA-Z0-9_=-]{1,256}$`)

// NotifyQQ sends only automation identifiers and the operation outcome to the
// explicitly configured recipient. A disabled transport is a no-op.
func NotifyQQ(ctx context.Context, app core.App, taskID, runID, action, outcome string) (bool, error) {
	d, err := getDestination(app)
	if err != nil {
		return false, errQQ
	}
	if !d.Enabled {
		return false, nil
	}
	for _, s := range []string{taskID, runID, action, outcome} {
		if !eventLabel.MatchString(s) {
			return false, errors.New("invalid DNS notification metadata")
		}
	}
	err = sendQQ(ctx, d, os.Getenv(secretEnv), fmt.Sprintf("DNS 自动化\n任务 %s\n执行 %s\n操作 %s\n结果 %s", taskID, runID, action, outcome), qqClient)
	return err == nil, err
}

// Use fixed Tencent API endpoints for both the token and the recipient. Remote
// error bodies can contain credentials and must never reach callers or logs.
func sendQQ(ctx context.Context, d destination, secret, content string, client *http.Client) error {
	if !d.Enabled || !appIDPattern.MatchString(d.AppID) || !recipientPattern.MatchString(d.OpenID) || secret == "" || content == "" {
		return errQQ
	}
	post := func(path string, payload any, token string, out any) error {
		body, err := json.Marshal(payload)
		if err != nil {
			return errQQ
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, qqAPI+path, bytes.NewReader(body))
		if err != nil {
			return errQQ
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "QQBot "+token)
		}
		res, err := client.Do(req)
		if err != nil {
			return errQQ
		}
		defer res.Body.Close()
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return errQQ
		}
		if err = json.NewDecoder(io.LimitReader(res.Body, 65536)).Decode(out); err != nil {
			return errQQ
		}
		return nil
	}
	var credential struct {
		Token string `json:"access_token"`
	}
	if err := post("/app/getAppAccessToken", map[string]string{"appId": d.AppID, "clientSecret": secret}, "", &credential); err != nil || credential.Token == "" {
		return errQQ
	}
	var receipt struct {
		ID string `json:"id"`
	}
	if err := post("/v2/users/"+d.OpenID+"/messages", map[string]any{"msg_type": 0, "content": content}, credential.Token, &receipt); err != nil || receipt.ID == "" {
		return errQQ
	}
	return nil
}

// BindWebhook registers a public Tencent callback under /api. Signed C2C
// events confirm contact only for the destination explicitly saved by an admin.
func BindWebhook(group *router.RouterGroup[*core.RequestEvent]) {
	group.POST("/dns-identity/qq/webhook", func(e *core.RequestEvent) error {
		d, err := getDestination(e.App)
		if err != nil || !d.Enabled {
			return e.NotFoundError("Callback is not enabled.", nil)
		}
		secret := os.Getenv(secretEnv)
		if secret == "" || e.Request.Header.Get("X-Bot-Appid") != d.AppID {
			return e.ForbiddenError("Invalid bot identity.", nil)
		}
		body, err := io.ReadAll(e.Request.Body)
		if err != nil {
			return e.BadRequestError("Invalid payload.", nil)
		}
		var event struct {
			Op   *int   `json:"op"`
			Type string `json:"t"`
			Data struct {
				Content    string `json:"content"`
				PlainToken string `json:"plain_token"`
				EventTS    string `json:"event_ts"`
				Author     struct {
					OpenID string `json:"user_openid"`
				} `json:"author"`
			} `json:"d"`
		}
		if json.Unmarshal(body, &event) != nil || event.Op == nil {
			return e.BadRequestError("Invalid payload.", nil)
		}
		seed := strings.Repeat(secret, 1+(ed25519.SeedSize-1)/len(secret))[:ed25519.SeedSize]
		key := ed25519.NewKeyFromSeed([]byte(seed))
		now := time.Now()
		fresh := func(raw string) bool {
			v, err := strconv.ParseInt(raw, 10, 64)
			return err == nil && strconv.FormatInt(v, 10) == raw && v >= now.Unix()-300 && v <= now.Unix()+300
		}
		if *event.Op == 13 {
			if !fresh(event.Data.EventTS) || !validationToken.MatchString(event.Data.PlainToken) {
				return e.BadRequestError("Invalid challenge.", nil)
			}
			sig := ed25519.Sign(key, []byte(event.Data.EventTS+event.Data.PlainToken))
			return e.JSON(200, map[string]string{"plain_token": event.Data.PlainToken, "signature": hex.EncodeToString(sig)})
		}
		timestamp := e.Request.Header.Get("X-Signature-Timestamp")
		signature, err := hex.DecodeString(e.Request.Header.Get("X-Signature-Ed25519"))
		if err != nil || !fresh(timestamp) || !ed25519.Verify(key.Public().(ed25519.PublicKey), append([]byte(timestamp), body...), signature) {
			return e.UnauthorizedError("Invalid signature.", nil)
		}
		if *event.Op == 0 && event.Type == "C2C_MESSAGE_CREATE" && recipientPattern.MatchString(event.Data.Author.OpenID) {
			stamp, _ := strconv.ParseInt(timestamp, 10, 64)
			if strings.HasPrefix(event.Data.Content, "bind-") {
				_, err := e.App.DB().NewQuery(`UPDATE dns_qq_notification SET open_id={:recipient},confirmed_at={:ts},bind_hash='',bind_expires=0
					WHERE id=1 AND enabled=1 AND app_id={:app} AND bind_hash={:hash} AND bind_expires>={:now}`).Bind(dbx.Params{
					"recipient": event.Data.Author.OpenID, "app": d.AppID, "ts": stamp, "hash": digest(strings.TrimSpace(event.Data.Content)), "now": now.Unix(),
				}).Execute()
				if err != nil {
					return e.InternalServerError("Could not bind recipient.", nil)
				}
			} else if event.Data.Author.OpenID == d.OpenID {
				if err := confirm(e.App, d, time.Unix(stamp, 0)); err != nil {
					return e.InternalServerError("Could not confirm destination.", nil)
				}
			}
		}
		return e.JSON(200, map[string]int{"op": 12, "d": 0})
	}).Bind(apis.BodyLimit(65536))
}
