package dnsmcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/mail"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"k8s.io/client-go/tools/clientcmd"

	"github.com/certimate-go/certimate/internal/certacme"
	"github.com/certimate-go/certimate/internal/domain"
)

// Keep only account parameters here. File paths, commands and deployment targets
// belong to the published workflow and cannot be set through the credential API.
type certAccountSpec struct {
	native, required, optional string
	aliases                    map[string]string
}

var issuerAccountSpecs = map[string]certAccountSpec{
	"letsencrypt": {"letsencrypt", "email", "mode", nil},
	"zerossl":     {"zerossl", "email", "eabMode eabKid eabHmacKey", eabAliases()},
	"google":      {"googletrustservices", "email", "mode eabMode eabKid eabHmacKey projectId serviceAccountKey", eabAliases()},
	"litessl":     {"litessl", "email eabKid eabHmacKey", "", eabAliases()},
	"customacme":  {"acmeca", "endpoint email", "eabKid eabHmacKey", map[string]string{"directory": "endpoint", "kid": "eabKid", "key": "eabHmacKey"}},
	"tencent":     {"tencentcloud", "secretId secretKey email", "projectId", nil},
	"aliyun":      {"aliyun", "accessKeyId accessKeySecret", "", nil},
	"ucloud":      {"ucloud", "publicKey privateKey email phone username", "projectId", nil},
}

func eabAliases() map[string]string { return map[string]string{"kid": "eabKid", "key": "eabHmacKey"} }

var deploymentAccountSpecs = map[string]certAccountSpec{
	"amh":               {"amh", "serverUrl username password", "", nil},
	"btpanel":           {"baotapanel", "serverUrl apiKey", "", map[string]string{"key": "apiKey"}},
	"btwin":             {"baotapanelgo", "serverUrl apiKey", "", map[string]string{"key": "apiKey"}},
	"kangle":            {"kangle", "serverUrl username", "password securityKey", map[string]string{"skey": "securityKey"}},
	"kangleadmin":       {"kangleadmin", "serverUrl username securityKey", "adminPath", map[string]string{"skey": "securityKey", "path": "adminPath"}},
	"safeline":          {"safeline", "serverUrl apiToken", "", map[string]string{"token": "apiToken"}},
	"btwaf":             {"baotawaf", "serverUrl apiKey", "", map[string]string{"key": "apiKey"}},
	"cdnfly":            {"cdnfly", "serverUrl apiKey apiSecret", "", map[string]string{"api_key": "apiKey", "api_secret": "apiSecret"}},
	"lecdn":             {"lecdn", "serverUrl authMethod apiRole apiVersion", "username password apiKey", map[string]string{"auth": "authMethod", "api_key": "apiKey", "email": "username"}},
	"goedge":            {"goedge", "serverUrl apiRole accessKeyId accessKey", "", map[string]string{"usertype": "apiRole"}},
	"uusec":             {"uusec", "serverUrl username password", "", nil},
	"samwaf":            {"samwaf", "serverUrl apiKey", "", map[string]string{"api_key": "apiKey"}},
	"opanel":            {"1panel", "serverUrl apiKey apiVersion", "", map[string]string{"version": "apiVersion", "key": "apiKey"}},
	"mwpanel":           {"mwpanel", "serverUrl appId appSecret", "", nil},
	"acepanel":          {"ratpanel", "serverUrl accessTokenId accessToken", "", map[string]string{"id": "accessTokenId", "token": "accessToken"}},
	"ratpanel":          {"ratpanel", "serverUrl accessTokenId accessToken", "", map[string]string{"id": "accessTokenId", "token": "accessToken"}},
	"xp":                {"xp", "serverUrl apiKey", "", nil},
	"cloudpanel":        {"cloudpanel", "serverUrl username password", "", nil},
	"directadmin":       {"directadmin", "serverUrl username password", "", nil},
	"synology":          {"synologydsm", "serverUrl username password", "totpSecret", nil},
	"lucky":             {"lucky", "serverUrl apiToken", "", map[string]string{"opentoken": "apiToken"}},
	"fnos":              {"fnos", "host port username password hostKeyFingerprint", "", nil},
	"iis":               {"iis", "host username password hostKeyFingerprint", "port", nil},
	"nginxproxymanager": {"nginxproxymanager", "serverUrl username password", "", map[string]string{"email": "username"}},
	"proxmox":           {"proxmoxve", "serverUrl apiToken apiTokenSecret", "", map[string]string{"api_user": "apiToken", "api_key": "apiTokenSecret"}},
	"k8s":               {"k8s", "kubeConfig", "", nil},
	"aliyun":            {"aliyun", "accessKeyId accessKeySecret", "", nil},
	"tencent":           {"tencentcloud", "secretId secretKey", "projectId", nil},
	"huawei":            {"huaweicloud", "accessKeyId secretAccessKey", "enterpriseProjectId", nil},
	"ucloud":            {"ucloud", "publicKey privateKey", "projectId", nil},
	"qiniu":             {"qiniu", "accessKey secretKey", "", nil},
	"doge":              {"dogecloud", "accessKey secretKey", "", nil},
	"axisnow":           {"axisnow", "apiToken", "", map[string]string{"token": "apiToken"}},
	"upyun":             {"upyun", "username password", "", nil},
	"baidu":             {"baiducloud", "accessKeyId secretAccessKey", "", nil},
	"ksyun":             {"ksyun", "accessKeyId secretAccessKey", "", nil},
	"huoshan":           {"volcengine", "accessKeyId secretAccessKey", "", nil},
	"west":              {"westcn", "username apiPassword", "", map[string]string{"api_password": "apiPassword"}},
	"wangsu":            {"wangsu", "accessKeyId accessKeySecret apiKey", "", map[string]string{"username": "accessKeyId", "spKey": "accessKeySecret"}},
	"baishan":           {"baishan", "apiToken", "", map[string]string{"token": "apiToken"}},
	"ctyun":             {"ctcccloud", "accessKeyId secretAccessKey", "", nil},
	"kuocai":            {"kuocai", "username password", "", nil},
	"qzyun":             {"qzyun", "email password", "", nil},
	"rainyun":           {"rainyun", "apiKey", "", nil},
	"unicloud":          {"unicloud", "username password", "", nil},
	"aws":               {"aws", "accessKeyId secretAccessKey", "", nil},
	"gcore":             {"gcore", "apiToken", "", map[string]string{"apikey": "apiToken"}},
	"cachefly":          {"cachefly", "apiToken", "", map[string]string{"apikey": "apiToken"}},
	"ssh":               {"ssh", "host port authMethod username", "password key keyPassphrase", map[string]string{"auth": "authMethod", "privatekey": "key", "passphrase": "keyPassphrase"}},
	"ftp":               {"ftp", "host port username password", "", nil},
	"s3storage":         {"s3", "endpoint accessKey secretKey", "", map[string]string{"AccessKeyId": "accessKey", "SecretAccessKey": "secretKey"}},
	"local":             {"local", "", "", nil},
}

func certAccountSpecs(deploy bool) map[string]certAccountSpec {
	if deploy {
		return deploymentAccountSpecs
	}
	return issuerAccountSpecs
}

func (s certAccountSpec) matchesNative(p string) bool {
	return s.native == p || s.native == "letsencrypt" && p == "letsencryptstaging"
}
func (s certAccountSpec) acme() bool {
	return slices.Contains([]string{"letsencrypt", "googletrustservices", "zerossl", "litessl", "acmeca"}, s.native)
}
func (s certAccountSpec) reserve() string {
	if s.acme() {
		return "ca"
	}
	return ""
}

func certAccountInputSchemas(deploy bool) map[string]object {
	out := map[string]object{}
	for kind, s := range certAccountSpecs(deploy) {
		inputs := object{}
		for _, field := range strings.Fields(s.required + " " + s.optional) {
			typ := "string"
			if field == "port" || field == "accessTokenId" || (field == "projectId" && s.native == "tencentcloud") {
				typ = "integer"
			}
			inputs[field] = object{"type": typ, "required": slices.Contains(strings.Fields(s.required), field)}
		}
		if kind == "google" && !deploy {
			inputs["mode"].(object)["enum"] = []string{"live", "staging"}
			inputs["eabMode"].(object)["enum"] = []string{"manual", "auto"}
			for _, field := range []string{"eabKid", "eabHmacKey"} {
				inputs[field].(object)["description"] = "Required for manual EAB (the default)."
			}
			inputs["projectId"].(object)["description"] = "Google Cloud project ID. Required for automatic EAB."
			inputs["serviceAccountKey"].(object)["description"] = "Google service account key JSON as a string. Required for automatic EAB."
		}
		row := object{"type": kind, "name": kind, "nativeProvider": s.native, "inputs": inputs}
		if deploy {
			row["taskinputs"] = object{"workflowId": object{"type": "string", "required": true}, "nodeId": object{"type": "string", "required": true}}
		}
		out[kind] = row
	}
	return out
}

func (s certAccountSpec) normalizedKey(k string) string {
	if alias := s.aliases[k]; alias != "" {
		return alias
	}
	if k == "url" {
		k = "serverUrl"
	}
	for _, name := range strings.Fields(s.required + " " + s.optional) {
		if strings.EqualFold(k, name) {
			return name
		}
	}
	return ""
}

func certAccountURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

func validInlineKubeConfig(raw string) bool {
	c, err := clientcmd.Load([]byte(raw))
	if err != nil || len(c.Contexts) == 0 || len(c.Clusters) == 0 || len(c.AuthInfos) == 0 || c.CurrentContext == "" || clientcmd.Validate(*c) != nil {
		return false
	}
	for _, a := range c.AuthInfos {
		if a == nil || a.Exec != nil || a.AuthProvider != nil || a.TokenFile != "" || a.ClientKey != "" || a.ClientCertificate != "" {
			return false
		}
	}
	for _, v := range c.Clusters {
		if v == nil || !certAccountURL(v.Server) || v.CertificateAuthority != "" || v.InsecureSkipTLSVerify || v.ProxyURL != "" {
			return false
		}
	}
	return true
}

func (s certAccountSpec) configure(cfg, patch object) (string, *opError) {
	seen := map[string]bool{}
	for k, input := range patch {
		raw, ok := input.(string)
		if !ok {
			switch n := input.(type) {
			case float64:
				raw = strconv.FormatFloat(n, 'f', -1, 64)
			case json.Number:
				raw = n.String()
			default:
				return "", invalid
			}
		}
		if len(raw) > 131072 || strings.ContainsRune(raw, '\x00') {
			return "", invalid
		}
		// DNSMgr account display hints are not part of a native provider config.
		if k == "proxy" && (raw == "0" || raw == "") || (k == "account" || k == "name") && s.normalizedKey(k) == "" {
			continue
		}
		if k == "auth" && s.native == "cdnfly" && raw == "0" {
			continue
		}
		if k == "auth" && s.native == "kangle" && (raw == "0" || raw == "1") {
			continue
		}
		if (k == "secure" && s.native == "ftp" || k == "windows" && s.native == "ssh") && raw == "0" {
			continue
		}
		key := s.normalizedKey(k)
		if key == "" || seen[key] {
			return "", invalid
		}
		seen[key] = true
		var value any = raw
		switch key {
		case "port", "accessTokenId", "projectId":
			if key != "projectId" || s.native == "tencentcloud" {
				n, err := strconv.ParseInt(raw, 10, 53)
				if err != nil || n < 0 || key == "accessTokenId" && n == 0 || key == "port" && (n < 1 || n > 65535) {
					return "", invalid
				}
				value = n
			}
		case "serverUrl", "endpoint":
			if !certAccountURL(raw) {
				return "", invalid
			}
		case "host":
			if raw == "" || strings.IndexFunc(raw, func(r rune) bool {
				return !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || strings.ContainsRune(".-:", r))
			}) >= 0 {
				return "", invalid
			}
		case "email":
			a, err := mail.ParseAddress(raw)
			if err != nil || a.Address != raw || a.Name != "" {
				return "", invalid
			}
		case "hostKeyFingerprint":
			v, ok := strings.CutPrefix(raw, "SHA256:")
			decoded, err := base64.RawStdEncoding.Strict().DecodeString(v)
			if !ok || err != nil || len(decoded) != 32 {
				return "", invalid
			}
		case "adminPath":
			if !strings.HasPrefix(raw, "/") || path.Clean(raw) != raw || strings.ContainsAny(raw, "?#%\\") {
				return "", invalid
			}
		case "kubeConfig":
			if !validInlineKubeConfig(raw) {
				return "", invalid
			}
		case "apiVersion":
			if s.native == "1panel" && (raw == "1" || raw == "2") {
				value = "v" + raw
			}
			if !slices.Contains([]string{"v1", "v2", "v3", "v4"}, value.(string)) {
				return "", invalid
			}
		case "apiRole":
			if !slices.Contains([]string{"user", "admin", "client", "master"}, raw) {
				return "", invalid
			}
		case "mode":
			if raw != "live" && raw != "staging" {
				return "", invalid
			}
		case "eabMode":
			if raw != "manual" && !((s.native == "zerossl" || s.native == "googletrustservices") && raw == "auto") {
				return "", unsupported
			}
		case "authMethod":
			if k == "auth" && raw == "0" {
				value = "password"
			}
			if k == "auth" && raw == "1" {
				if s.native == "ssh" {
					value = "key"
				} else {
					value = "apikey"
				}
			}
			if value != "password" && !(s.native == "ssh" && value == "key") && !(s.native == "lecdn" && value == "apikey") {
				return "", invalid
			}
		}
		if key != "kubeConfig" && key != "key" && key != "serviceAccountKey" && strings.IndexFunc(raw, unicode.IsControl) >= 0 {
			return "", invalid
		}
		// Redirecting an existing credential can disclose private material at its next use.
		if slices.Contains([]string{"serverUrl", "endpoint", "host", "port", "adminPath", "hostKeyFingerprint", "kubeConfig"}, key) && cfg[key] != nil && str(cfg, key) != raw {
			if key != "port" || str(cfg, key) != strconv.FormatInt(value.(int64), 10) {
				return "", accountChangeConflict
			}
		}
		cfg[key] = value
	}
	native := s.native
	if native == "letsencrypt" && cfg["mode"] == "staging" {
		native = "letsencryptstaging"
	}
	switch native {
	case "aws":
		cfg["authMethod"] = "accesskey"
	case "nginxproxymanager":
		cfg["authMethod"] = "password"
	case "goedge":
		if _, ok := cfg["apiRole"]; !ok {
			cfg["apiRole"] = "user"
		}
	case "1panel":
		if _, ok := cfg["apiVersion"]; !ok {
			cfg["apiVersion"] = "v2"
		}
	case "lecdn":
		if cfg["apiVersion"] == nil {
			cfg["apiVersion"] = "v4"
		}
		if cfg["apiRole"] == nil {
			cfg["apiRole"] = "client"
		}
	case "kangle":
		if (str(cfg, "password") == "") == (str(cfg, "securityKey") == "") {
			return "", invalid
		}
	}
	for _, k := range strings.Fields(s.required) {
		if cfg[k] == nil || cfg[k] == "" {
			return "", invalid
		}
	}
	if native == "googletrustservices" {
		inactive := []string{"projectId", "serviceAccountKey"}
		if str(cfg, "eabMode") == "auto" {
			inactive = []string{"eabKid", "eabHmacKey"}
		} else if str(cfg, "eabKid") == "" || str(cfg, "eabHmacKey") == "" {
			return "", invalid
		}
		for _, field := range inactive {
			if seen[field] && str(cfg, field) != "" {
				return "", invalid
			}
			delete(cfg, field)
		}
		if _, err := certacme.CreateACMEConfig(context.Background(), &certacme.ACMEConfigOptions{
			CAProvider: domain.CAProviderTypeGoogleTrustServices, CAProviderAccessConfig: cfg,
		}); err != nil {
			return "", invalid
		}
	}
	switch cfg["authMethod"] {
	case "password":
		if str(cfg, "username") == "" || str(cfg, "password") == "" {
			return "", invalid
		}
	case "apikey":
		if str(cfg, "apiKey") == "" {
			return "", invalid
		}
	case "key":
		if str(cfg, "key") == "" {
			return "", invalid
		}
	}
	if (str(cfg, "eabKid") == "") != (str(cfg, "eabHmacKey") == "") || cfg["eabMode"] == "manual" && str(cfg, "eabKid") == "" || cfg["eabMode"] == "auto" && str(cfg, "eabKid") != "" {
		return "", invalid
	}
	return native, nil
}
