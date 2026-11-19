package notifiers

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (r roundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return r(req) }

func TestDNSMgrNotificationTransports(t *testing.T) {
	const secret = "synthetic-private-key"
	credentials := map[string]any{
		"apiKey": secret, "apiUser": "testuser", "senderAddress": "sender@example.test", "receiverAddress": "recipient@example.test",
		"accessKeyId": "testid", "accessKeySecret": secret, "appToken": secret, "uid": "UID_test",
	}
	for _, provider := range []domain.NotificationProviderType{sendCloud, aliyunMail, wxPusher} {
		t.Run(string(provider), func(t *testing.T) {
			f, err := Registries.Get(provider)
			if err != nil {
				t.Fatal(err)
			}
			n, err := f(&ProviderFactoryOptions{ProviderAccessConfig: credentials})
			if err != nil {
				t.Fatal(err)
			}
			c := n.(*apiChannel)
			success := true
			c.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
				if r.URL.Scheme != "https" || r.Method != "POST" || r.URL.RawQuery != "" {
					t.Fatal("incorrect transport")
				}
				var reply string
				switch provider {
				case wxPusher:
					if r.URL.Host != "wxpusher.zjiecode.com" || r.URL.Path != "/api/send/message" {
						t.Fatal("incorrect WxPusher endpoint")
					}
					var body struct {
						AppToken, Content, Summary string
						ContentType                int
						UIDs                       []string
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AppToken != secret || body.Content != "body<>&" || body.Summary != "subject" || body.ContentType != 3 || len(body.UIDs) != 1 || body.UIDs[0] != "UID_test" {
						t.Fatal("incorrect WxPusher request")
					}
					reply = `{"code":1000,"success":true,"data":[{"code":1000,"uid":"UID_test"}]}`
					if !success {
						reply = `{"code":1000,"success":true,"data":[{"code":1001,"uid":"UID_test"}]}`
					}
				case sendCloud:
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					p := r.PostForm
					if r.URL.Host != "api.sendcloud.net" || r.URL.Path != "/apiv2/mail/send" || p.Get("apiKey") != secret || p.Get("apiUser") != "testuser" || p.Get("subject") != "subject" || p.Get("html") != "body&lt;&gt;&amp;" || p.Get("to") != "recipient@example.test" || p.Get("from") != "sender@example.test" {
						t.Fatal("incorrect SendCloud request")
					}
					reply = `{"statusCode":200,"result":true}`
					if !success {
						reply = `{"statusCode":40005,"message":"synthetic-private-key"}`
					}
				case aliyunMail:
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					p := r.PostForm
					signature := p.Get("Signature")
					p.Del("Signature")
					canonical := strings.ReplaceAll(p.Encode(), "+", "%20")
					h := hmac.New(sha1.New, []byte(secret+"&"))
					h.Write([]byte("POST&%2F&" + url.QueryEscape(canonical)))
					if r.URL.Host != "dm.aliyuncs.com" || p.Get("Action") != "SingleSendMail" || p.Get("ToAddress") != "recipient@example.test" || p.Get("HtmlBody") != "body&lt;&gt;&amp;" || p.Get("AccessKeyId") != "testid" || p.Get("SignatureNonce") == "" || base64.StdEncoding.EncodeToString(h.Sum(nil)) != signature {
						t.Fatal("invalid DirectMail signature or payload")
					}
					reply = `{"RequestId":"synthetic-request-id"}`
					if !success {
						reply = `{"Code":"rejected","Message":"synthetic-private-key","RequestId":"test"}`
					}
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(reply)), Header: make(http.Header), Request: r}, nil
			})
			if _, err := n.Notify(context.Background(), "subject", "body<>&"); err != nil {
				t.Fatal(err)
			}
			success = false
			if _, err := n.Notify(context.Background(), "subject", "body<>&"); err == nil || strings.Contains(err.Error(), secret) {
				t.Fatal("provider rejection should be redacted")
			}
		})
	}
}
