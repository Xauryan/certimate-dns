package dnsmgredge

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

func (d *deployer) deployUUSEC(ctx context.Context, cert, key string) error {
	var auth struct{ Token string }
	if err := d.jsonRequest(ctx, http.MethodPost, "/api/v1/users/login", map[string]string{
		"usr": d.username, "pwd": d.secret, "otp": "",
	}, &auth, nil); err != nil {
		return fmt.Errorf("UUSEC login: %w", err)
	}
	if auth.Token == "" {
		return errors.New("UUSEC login did not return an access token")
	}
	params := map[string]any{"id": d.certID, "name": d.name, "type": 1, "crt": cert, "key": key}
	var reply string
	if err := d.jsonRequest(ctx, http.MethodPut, "/api/v1/certs", params, &reply, http.Header{"Authorization": {"Bearer " + auth.Token}}); err != nil {
		return fmt.Errorf("UUSEC certificate update: %w", err)
	}
	if reply != "OK" {
		return errors.New("UUSEC did not confirm certificate update")
	}
	return nil
}

func (d *deployer) deployXP(ctx context.Context, cert, key string) error {
	headers := http.Header{"XP-API-KEY": {d.secret}}
	var listing struct {
		Code int
		Data []struct {
			ID   json.Number
			Name string
		}
	}
	if err := d.jsonRequest(ctx, http.MethodGet, "/openApi/siteList", nil, &listing, headers); err != nil {
		return fmt.Errorf("XP site list: %w", err)
	}
	if listing.Code != 1000 {
		return errors.New("XP could not list sites")
	}
	ids := map[string]int64{}
	for _, site := range listing.Data {
		if !slices.Contains(d.targets, site.Name) {
			continue
		}
		if _, ok := ids[site.Name]; ok {
			return errors.New("XP returned ambiguous site names")
		}
		n, err := strconv.ParseInt(site.ID.String(), 10, 64)
		if err != nil || n <= 0 {
			return errors.New("XP returned invalid site ID")
		}
		ids[site.Name] = n
	}
	if len(ids) != len(d.targets) {
		return errors.New("one or more selected XP sites do not exist")
	}
	for i, target := range d.targets {
		var reply struct{ Code int }
		err := d.jsonRequest(ctx, http.MethodPost, "/openApi/setSSL", map[string]any{"id": ids[target], "key": key, "pem": cert}, &reply, headers)
		if err != nil || reply.Code != 1000 {
			return fmt.Errorf("XP confirmed %d of %d site updates; check the remaining sites before retrying", i, len(ids))
		}
	}
	return nil
}

type luckyRecord struct {
	Key           string
	Remark        string
	Enable        bool
	MappingToPath bool
	AllSyncClient bool
	CertsInfo     struct{ Domains []string }
}

func (d *deployer) deployLucky(ctx context.Context, cert, key string, leaf *x509.Certificate) error {
	headers := http.Header{"openToken": {d.secret}}
	var listing struct {
		Ret  *int
		List []luckyRecord
	}
	if err := d.jsonRequest(ctx, http.MethodGet, "/api/ssl", nil, &listing, headers); err != nil {
		return fmt.Errorf("Lucky certificate list: %w", err)
	}
	if listing.Ret == nil || *listing.Ret != 0 {
		return errors.New("Lucky could not list certificates")
	}
	targets := d.targets
	if len(targets) == 0 {
		targets = leaf.DNSNames
	}
	wanted := make(map[string]bool, len(targets))
	for _, target := range targets {
		wanted[strings.ToLower(strings.TrimSuffix(target, "."))] = false
	}
	var matched []luckyRecord
	seen := map[string]bool{}
	for _, record := range listing.List {
		match := false
		for _, domain := range record.CertsInfo.Domains {
			n := strings.ToLower(strings.TrimSuffix(domain, "."))
			if _, ok := wanted[n]; ok {
				wanted[n] = true
				match = true
			}
		}
		if !match {
			continue
		}
		if record.Key == "" || seen[record.Key] {
			return errors.New("Lucky returned an invalid certificate ID")
		}
		for _, domain := range record.CertsInfo.Domains {
			if leaf.VerifyHostname(domain) != nil {
				return errors.New("replacement certificate does not cover all names on the Lucky certificate")
			}
		}
		if record.MappingToPath {
			return errors.New("a selected Lucky certificate uses filesystem mapping")
		}
		seen[record.Key] = true
		matched = append(matched, record)
	}
	if len(matched) == 0 {
		return errors.New("no matching Lucky certificate entries")
	}
	// With explicit targets, check that every one was found before writing.
	if len(d.targets) > 0 {
		for _, found := range wanted {
			if !found {
				return errors.New("one or more selected Lucky domains do not exist")
			}
		}
	}
	for i, record := range matched {
		var reply struct{ Ret *int }
		payload := map[string]any{
			"Key": record.Key, "Remark": record.Remark, "Enable": record.Enable,
			"AddFrom": "file", "MappingToPath": false, "AllSyncClient": record.AllSyncClient,
			"CertBase64": base64.StdEncoding.EncodeToString([]byte(cert)), "KeyBase64": base64.StdEncoding.EncodeToString([]byte(key)),
		}
		err := d.jsonRequest(ctx, http.MethodPut, "/api/ssl", payload, &reply, headers)
		if err != nil || reply.Ret == nil || *reply.Ret != 0 {
			return fmt.Errorf("Lucky confirmed %d of %d certificate updates; check remote state before retrying", i, len(matched))
		}
	}
	return nil
}
