package dnsidentity

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"net/http"
	"sync"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/security"
	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

const guardKey = "dns.identity.loginGuard"
const guardLimit = 4096

type captchaChallenge struct {
	expires    time.Time
	ip, answer string
}
type loginGuard struct {
	mu         sync.Mutex
	challenges map[string]captchaChallenge
}

func newLoginGuard() *loginGuard {
	return &loginGuard{challenges: map[string]captchaChallenge{}}
}

func (g *loginGuard) purge(now time.Time) {
	for k, c := range g.challenges {
		if !c.expires.After(now) {
			delete(g.challenges, k)
		}
	}
}

func captchaRequired(app core.App) (bool, error) {
	var enabled bool
	err := app.DB().NewQuery("SELECT captcha FROM dns_login_policy WHERE id=1").Row(&enabled)
	return enabled, err
}

func (g *loginGuard) password(e *core.RecordAuthWithPasswordRequestEvent) error {
	required, err := captchaRequired(e.App)
	if err != nil {
		return err
	}
	var input struct {
		ID     string `json:"captchaId" form:"captchaId"`
		Answer string `json:"captcha" form:"captcha"`
	}
	if required {
		if err := e.BindBody(&input); err != nil {
			return err
		}
	}
	key := e.RealIP()
	now := time.Now()
	if required {
		g.mu.Lock()
		challenge, ok := g.challenges[input.ID]
		if ok && challenge.ip == key {
			delete(g.challenges, input.ID)
		}
		g.mu.Unlock()
		if !ok || !challenge.expires.After(now) || challenge.ip != key || subtle.ConstantTimeCompare([]byte(challenge.answer), []byte(input.Answer)) != 1 {
			return e.BadRequestError("Invalid or expired image code.", nil)
		}
	}
	// Reserve the attempt before checking credentials, including when multiple
	// requests arrive concurrently or the server restarts between attempts.
	params := dbx.Params{"source": digest(key), "expires": now.Add(2 * time.Hour).Unix()}
	var attempt int64
	err = e.App.RunInTransaction(func(tx core.App) error {
		if _, err := tx.DB().NewQuery("DELETE FROM dns_login_attempts WHERE expires <= {:now}").Bind(dbx.Params{"now": now.Unix()}).Execute(); err != nil {
			return err
		}
		res, err := tx.DB().NewQuery(`INSERT INTO dns_login_attempts(source,expires) SELECT {:source},{:expires}
			WHERE (SELECT COUNT(*) FROM dns_login_attempts WHERE source={:source}) < 5`).Bind(params).Execute()
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil || n == 0 {
			return err
		}
		attempt, err = res.LastInsertId()
		return err
	})
	if err != nil {
		return e.InternalServerError("Could not verify sign-in attempts.", nil)
	}
	if attempt == 0 {
		return e.TooManyRequestsError("Too many login attempts. Try again later.", nil)
	}
	err = e.Next()
	// A validated password may lead to a 401 (native MFA / authenticator).
	if e.Record != nil && (err == nil || e.Written() && e.Status() == http.StatusUnauthorized) && !e.Record.GetBool("disabled") {
		_, clearErr := e.App.DB().NewQuery("DELETE FROM dns_login_attempts WHERE source = {:source} AND id <= {:attempt}").Bind(dbx.Params{"source": params["source"], "attempt": attempt}).Execute()
		if clearErr != nil {
			e.App.Logger().Warn("Could not clear member sign-in attempts")
		}
	}
	return err
}

func serveCaptcha(e *core.RequestEvent) error {
	required, err := captchaRequired(e.App)
	if err != nil {
		return err
	}
	e.Response.Header().Set("Cache-Control", "no-store")
	if !required {
		return e.JSON(200, map[string]bool{"required": false})
	}
	g, ok := e.App.Store().Get(guardKey).(*loginGuard)
	if !ok {
		return e.InternalServerError("Sign-in is unavailable.", nil)
	}
	answer := security.RandomStringWithAlphabet(5, "23456789ABCDEFGHJKMNPQRSTUVWXYZ")
	id := security.RandomString(32)
	g.mu.Lock()
	if len(g.challenges) >= guardLimit {
		g.purge(time.Now())
	}
	if len(g.challenges) >= guardLimit {
		g.mu.Unlock()
		return e.TooManyRequestsError("Too many image challenges.", nil)
	}
	g.challenges[id] = captchaChallenge{expires: time.Now().Add(2 * time.Minute), ip: e.RealIP(), answer: answer}
	g.mu.Unlock()
	img := image.NewRGBA(image.Rect(0, 0, 64, 25))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.RGBA{244, 246, 249, 255}), image.Point{}, draw.Src)
	for i, r := range answer {
		pen := font.Drawer{Dst: img, Src: image.NewUniform(color.RGBA{35, 55, 85, 255}), Face: basicfont.Face7x13, Dot: fixed.P(4+i*12, 15+int(id[i])%5)}
		pen.DrawString(string(r))
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return err
	}
	return e.JSON(200, map[string]any{"required": true, "id": id, "image": "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())})
}
