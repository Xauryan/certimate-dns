package cloudflare

import "net/http"

type Options struct {
	ApiToken               string
	apiEmail, globalAPIKey string
	accountID              string
	dnsTransport           http.RoundTripper
}

type OptionsFunc func(*Options)

func WithApiToken(apiToken string) OptionsFunc {
	return func(o *Options) {
		o.ApiToken = apiToken
	}
}

func WithGlobalAPIKey(email, key string) OptionsFunc {
	return func(o *Options) { o.apiEmail = email; o.globalAPIKey = key }
}

// WithAccountID selects the billing account for creating a DNS zone.
func WithAccountID(id string) OptionsFunc { return func(o *Options) { o.accountID = id } }

// WithDNSTransport sends DNS requests over the account's configured transport.
func WithDNSTransport(transport http.RoundTripper) OptionsFunc {
	return func(o *Options) { o.dnsTransport = transport }
}
