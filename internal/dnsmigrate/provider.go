package dnsmigrate

import (
	"errors"
	"strings"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

// DNSMgr driver IDs differ from the Certimate credential provider IDs. The
// native driver registry decides which of these are available in this build.
var providers = map[string]string{
	"aliyun": "aliyun", "aliyunesa": "aliyunesa", "aws": "aws", "baidu": "baiducloud",
	"bt": "bt", "cloudflare": "cloudflare", "dnsla": "dnsla", "dnsmgr": "dnsmgr",
	"dnspod": "tencentcloud", "dynv6": "dynv6", "goedge": "goedge", "henet": "henet",
	"huawei": "huaweicloud", "huoshan": "volcengine", "jdcloud": "jdcloud", "namesilo": "namesilo",
	"powerdns": "powerdns", "qingcloud": "qingcloud", "spaceship": "spaceship",
	"technitium": "technitiumdns", "tencenteo": "tencenteo", "west": "westcn",
}

func nativeProvider(name string) string {
	id := providers[name]
	if !dns.IsSupportedProvider(id) {
		return ""
	}
	return id
}

func zoneIdentity(provider string, z Zone) (string, error) {
	switch provider {
	case "aliyun", "dnspod", "baidu", "dynv6", "huoshan", "namesilo", "qingcloud", "spaceship", "technitium", "west":
		return z.Name, nil
	case "cloudflare":
		if !cfID.MatchString(z.ProviderID) {
			return "", errors.New("Cloudflare zone ID missing or invalid")
		}
		return strings.ToLower(z.ProviderID), nil
	default:
		if z.ProviderID == "" {
			return "", errors.New("provider zone ID missing")
		}
		return z.ProviderID, nil
	}
}

// Some DNSMgr record IDs are array offsets or encode arbitrary record contents.
// Copy only known provider-assigned IDs. Re-select records from a fresh
// inventory for other adapters before creating an executable definition.
func hasStableRecordID(provider string) bool {
	switch provider {
	case "aliyun", "aliyunesa", "baidu", "bt", "cloudflare", "dnsla", "dnspod", "dynv6", "goedge", "henet", "huoshan", "jdcloud", "namesilo", "tencenteo", "west":
		return true
	}
	return false
}
