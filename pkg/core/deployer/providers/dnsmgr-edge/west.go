package dnsmgredge

import (
	"context"
	"crypto/md5"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

func (d *deployer) westCall(ctx context.Context, cmd string, fields url.Values, out any) error {
	if fields == nil {
		fields = url.Values{}
	}
	stamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	// The v2 API signs the account, API password and Unix milliseconds as supplied.
	signature := md5.Sum([]byte(d.username + d.secret + stamp))
	fields.Set("act", "vhostssl")
	fields.Set("cmd", cmd)
	fields.Set("sitename", d.targets[0])
	fields.Set("time", stamp)
	fields.Set("username", d.username)
	fields.Set("token", hex.EncodeToString(signature[:]))
	b, err := d.request(ctx, http.MethodPost, "/vhost/", "application/x-www-form-urlencoded", strings.NewReader(fields.Encode()), nil)
	if err != nil {
		return err
	}
	var response struct {
		Result json.Number
		Data   json.RawMessage
	}
	if !utf8.Valid(b) {
		b, err = simplifiedchinese.GBK.NewDecoder().Bytes(b)
	}
	if err != nil || json.Unmarshal(b, &response) != nil || response.Result.String() != "200" {
		return errors.New("West.cn did not confirm the operation")
	}
	if out != nil && (len(response.Data) == 0 || string(response.Data) == "null" || json.Unmarshal(response.Data, out) != nil) {
		return errors.New("West.cn returned invalid site metadata")
	}
	return nil
}

func (d *deployer) deployWest(ctx context.Context, cert, key string, leaf *x509.Certificate) error {
	var before struct {
		Enabled json.Number `json:"SSLEnabled"`
	}
	if err := d.westCall(ctx, "info", nil, &before); err != nil {
		return fmt.Errorf("West.cn site lookup: %w", err)
	}
	if before.Enabled != "0" && before.Enabled != "1" {
		return errors.New("West.cn returned unknown SSL activation status")
	}
	if err := d.westCall(ctx, "import", url.Values{"keycontent": {key}, "certcontent": {cert}}, nil); err != nil {
		return fmt.Errorf("West.cn certificate import: %w", err)
	}
	if before.Enabled == "0" {
		if err := d.westCall(ctx, "openssl", nil, nil); err != nil {
			return fmt.Errorf("West.cn certificate imported; enabling SSL: %w", err)
		}
		return nil
	}
	var after struct{ SSLCert struct{ SSL json.RawMessage } }
	if err := d.westCall(ctx, "info", nil, &after); err != nil {
		return fmt.Errorf("West.cn certificate imported; cache lookup: %w", err)
	}
	if len(after.SSLCert.SSL) == 0 || string(after.SSLCert.SSL) == "[]" || string(after.SSLCert.SSL) == "null" {
		return nil
	}
	var bindings map[string]struct{ SysID json.Number }
	if json.Unmarshal(after.SSLCert.SSL, &bindings) != nil {
		return errors.New("West.cn certificate imported; invalid SSL binding list")
	}
	// DNSMgr refreshes cache entries named in this certificate's domain list.
	// A wildcard SAN must not extend the operation to unrelated site bindings.
	var domains []string
	for domain, binding := range bindings {
		named := slices.ContainsFunc(leaf.DNSNames, func(san string) bool {
			return strings.EqualFold(strings.TrimSuffix(san, "."), strings.TrimSuffix(domain, "."))
		})
		if !named {
			continue
		}
		if n, err := binding.SysID.Int64(); err != nil || n <= 0 {
			return errors.New("West.cn certificate imported; invalid SSL binding ID")
		}
		domains = append(domains, domain)
	}
	slices.Sort(domains)
	for i, domain := range domains {
		fields := url.Values{"sslid": {bindings[domain].SysID.String()}, "dm": {domain}}
		if err := d.westCall(ctx, "clearsslcache", fields, nil); err != nil {
			return fmt.Errorf("West.cn certificate imported; %d of %d cache updates confirmed: %w", i, len(domains), err)
		}
	}
	return nil
}
