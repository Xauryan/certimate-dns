// Notification transports used by DNSMgr for API email and WeChat subscriptions.
package notifiers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/pkg/core"
	xmaps "github.com/certimate-go/certimate/pkg/utils/maps"
)

const (
	sendCloud  domain.NotificationProviderType = "sendcloud"
	aliyunMail domain.NotificationProviderType = "aliyunmail"
	wxPusher   domain.NotificationProviderType = "wxpusher"
)

func init() {
	for _, provider := range []domain.NotificationProviderType{sendCloud, aliyunMail, wxPusher} {
		Registries.MustRegister(provider, func(o *ProviderFactoryOptions) (core.Notifier, error) {
			return newAPIChannel(provider, o)
		})
	}
}

type apiChannel struct {
	provider                 domain.NotificationProviderType
	client                   *http.Client
	key, secret              string
	sender, alias, recipient string
}

func newAPIChannel(provider domain.NotificationProviderType, o *ProviderFactoryOptions) (*apiChannel, error) {
	value := func(key string) string { return xmaps.GetString(o.ProviderAccessConfig, key) }
	c := &apiChannel{
		provider: provider,
		client:   &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	switch provider {
	case sendCloud:
		c.key, c.secret = value("apiUser"), value("apiKey")
	case aliyunMail:
		c.key, c.secret = value("accessKeyId"), value("accessKeySecret")
	case wxPusher:
		c.key, c.recipient = value("appToken"), value("uid")
		if c.key == "" || c.recipient == "" {
			return nil, errors.New("WxPusher requires an application token and recipient UID")
		}
		return c, nil
	default:
		return nil, errors.New("unknown notification provider")
	}
	c.sender, c.alias = value("senderAddress"), value("senderName")
	c.recipient = xmaps.GetOrDefaultString(o.ProviderExtendedConfig, "receiverAddress", value("receiverAddress"))
	if c.key == "" || c.secret == "" {
		return nil, errors.New("mail API credentials are required")
	}
	for _, address := range []string{c.sender, c.recipient} {
		parsed, err := mail.ParseAddress(address)
		if err != nil || parsed.Address != address {
			return nil, errors.New("sender and recipient must each be an email address")
		}
	}
	return c, nil
}

func (*apiChannel) SetLogger(*slog.Logger) {}

func (c *apiChannel) Notify(ctx context.Context, subject, message string) (*core.NotifierNotifyResult, error) {
	var err error
	switch c.provider {
	case sendCloud:
		err = c.sendSendCloud(ctx, subject, message)
	case aliyunMail:
		err = c.sendAliyunMail(ctx, subject, message)
	case wxPusher:
		err = c.sendWxPusher(ctx, subject, message)
	default:
		return nil, errors.New("unknown notification provider")
	}
	if err != nil {
		return nil, err
	}
	return &core.NotifierNotifyResult{}, nil
}

func (c *apiChannel) post(ctx context.Context, endpoint, mediaType string, body io.Reader, result any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return errors.New("invalid notification endpoint")
	}
	req.Header.Set("Content-Type", mediaType)
	resp, err := c.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("notification request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s returned HTTP %d", c.provider, resp.StatusCode)
	}
	const limit = 64 << 10
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || len(data) > limit || json.Unmarshal(data, result) != nil {
		return errors.New("invalid notification provider response")
	}
	return nil
}

func mailHTML(message string) string {
	return strings.ReplaceAll(html.EscapeString(strings.ReplaceAll(message, "\r\n", "\n")), "\n", "<br/>")
}

func (c *apiChannel) sendSendCloud(ctx context.Context, subject, message string) error {
	fields := url.Values{
		"apiUser": {c.key}, "apiKey": {c.secret},
		"from": {c.sender}, "to": {c.recipient}, "subject": {subject}, "html": {mailHTML(message)},
	}
	if c.alias != "" {
		fields.Set("fromName", c.alias)
	}
	var reply struct {
		Result     bool
		StatusCode int
	}
	if err := c.post(ctx, "https://api.sendcloud.net/apiv2/mail/send", "application/x-www-form-urlencoded", strings.NewReader(fields.Encode()), &reply); err != nil {
		return err
	}
	if !reply.Result || reply.StatusCode != 200 {
		return fmt.Errorf("SendCloud rejected the message (code %d)", reply.StatusCode)
	}
	return nil
}

func (c *apiChannel) sendAliyunMail(ctx context.Context, subject, message string) error {
	fields := url.Values{
		"Action": {"SingleSendMail"}, "AccountName": {c.sender}, "AddressType": {"1"}, "ReplyToAddress": {"false"},
		"Subject": {subject}, "HtmlBody": {mailHTML(message)}, "ToAddress": {c.recipient},
		"Format": {"JSON"}, "Version": {"2015-11-23"}, "RegionId": {"cn-hangzhou"}, "AccessKeyId": {c.key},
		"SignatureMethod": {"HMAC-SHA1"}, "SignatureVersion": {"1.0"}, "SignatureNonce": {rand.Text()},
		"Timestamp": {time.Now().UTC().Format(time.RFC3339)},
	}
	if c.alias != "" {
		fields.Set("FromAlias", c.alias)
	}
	parameters := make(map[string]*string, len(fields))
	for name, values := range fields {
		parameters[name] = &values[0]
	}
	method := http.MethodPost
	fields.Set("Signature", *openapi.GetRPCSignature(parameters, &method, &c.secret))
	var reply struct {
		RequestID string `json:"RequestId"`
		Code      string
	}
	if err := c.post(ctx, "https://dm.aliyuncs.com/", "application/x-www-form-urlencoded", strings.NewReader(fields.Encode()), &reply); err != nil {
		return err
	}
	if reply.Code != "" || reply.RequestID == "" {
		return errors.New("Alibaba Cloud DirectMail rejected the message")
	}
	return nil
}

func (c *apiChannel) sendWxPusher(ctx context.Context, subject, message string) error {
	summary := []rune(subject)
	if len(summary) > 100 {
		summary = summary[:100]
	}
	payload, err := json.Marshal(map[string]any{"appToken": c.key, "content": message, "summary": string(summary), "contentType": 3, "uids": []string{c.recipient}})
	if err != nil {
		return err
	}
	var reply struct {
		Code    int
		Success bool
		Data    []struct {
			UID  string
			Code int
		}
	}
	if err := c.post(ctx, "https://wxpusher.zjiecode.com/api/send/message", "application/json", bytes.NewReader(payload), &reply); err != nil {
		return err
	}
	if !reply.Success || reply.Code != 1000 || len(reply.Data) != 1 || reply.Data[0].UID != c.recipient || reply.Data[0].Code != 1000 {
		return errors.New("WxPusher did not accept the recipient's message")
	}
	return nil
}
