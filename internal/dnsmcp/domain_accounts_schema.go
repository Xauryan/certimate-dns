package dnsmcp

import (
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

// These are the credential names used by DNSMgr clients. Only the names on the
// right enter the existing Certimate access record used by the DNS driver.
type accountDefinition struct {
	native string
	label  string
	fields map[string]string
}

var keyPair = map[string]string{"AccessKeyId": "accessKeyId", "AccessKeySecret": "accessKeySecret"}
var secretPair = map[string]string{"AccessKeyId": "accessKeyId", "SecretAccessKey": "secretAccessKey"}
var tencentPair = map[string]string{"SecretId": "secretId", "SecretKey": "secretKey"}
var accountDefinitions = map[string]accountDefinition{
	"aliyun":     {"aliyun", "阿里云", keyPair},
	"dnspod":     {"tencentcloud", "腾讯云 DNSPod", tencentPair},
	"huawei":     {"huaweicloud", "华为云", secretPair},
	"baidu":      {"baiducloud", "百度云", secretPair},
	"west":       {"westcn", "西部数码", map[string]string{"username": "username", "api_password": "apiPassword"}},
	"huoshan":    {"volcengine", "火山引擎", secretPair},
	"jdcloud":    {"jdcloud", "京东云", keyPair},
	"dnsla":      {"dnsla", "DNSLA", map[string]string{"apiid": "apiId", "apisecret": "apiSecret"}},
	"qingcloud":  {"qingcloud", "青云", map[string]string{"access_key_id": "accessKeyId", "secret_access_key": "secretAccessKey"}},
	"bt":         {"bt", "宝塔域名", map[string]string{"AccessKey": "accessKey", "SecretKey": "secretKey", "AccountID": "accountId"}},
	"cloudflare": {"cloudflare", "Cloudflare", map[string]string{"apikey": "apiToken"}},
	"aws":        {"aws", "AWS Route 53", secretPair},
	"namesilo":   {"namesilo", "NameSilo", map[string]string{"apikey": "apiKey"}},
	"henet":      {"henet", "HE DNS", map[string]string{"username": "username", "password": "password"}},
	"spaceship":  {"spaceship", "Spaceship", map[string]string{"apikey": "apiKey", "apisecret": "apiSecret"}},
	"powerdns":   {"powerdns", "PowerDNS", map[string]string{"serverUrl": "serverUrl", "apikey": "apiKey"}},
	"technitium": {"technitiumdns", "Technitium DNS", map[string]string{"url": "serverUrl", "token": "apiToken"}},
	"aliyunesa":  {"aliyunesa", "阿里云 ESA", map[string]string{"AccessKeyId": "accessKeyId", "AccessKeySecret": "accessKeySecret", "region": "region"}},
	"tencenteo":  {"tencenteo", "腾讯云 EdgeOne", map[string]string{"SecretId": "secretId", "SecretKey": "secretKey", "site_type": "siteType"}},
	"dnsmgr":     {"dnsmgr", "DNSMgr", map[string]string{"base_url": "serverUrl", "uid": "uid", "key": "apiKey"}},
	"goedge":     {"goedge", "GoEdge", map[string]string{"base_url": "serverUrl", "accessKeyId": "accessKeyId", "accessKey": "accessKey", "type": "apiRole", "nsClusterId": "nsClusterId", "userId": "userId"}},
	"dynv6":      {"dynv6", "dynv6", map[string]string{"token": "httpToken"}},
}

func nativeAccountType(id string) string {
	if def, ok := accountDefinitions[id]; ok {
		return def.native
	}
	return id
}
func legacyAccountType(id string) string {
	for legacy, def := range accountDefinitions {
		if def.native == id {
			return legacy
		}
	}
	return id
}

func accountInputs(t string, def accountDefinition) object {
	inputs := object{"proxy": object{"type": "string", "enum": []string{"0", "1"}, "nativeField": "dnsManagementProxy", "required": false, "description": "0 uses a direct connection. 1 selects the administrator-configured DNS proxy. Omit to keep the default transport."}}
	for legacy, native := range def.fields {
		required := !slices.Contains([]string{"region", "site_type", "userId", "type"}, legacy)
		inputs[legacy] = object{"type": "string", "required": required, "nativeField": native}
	}
	if t == "powerdns" {
		inputs["serverUrl"] = object{"type": "string", "description": "Base URL. Alternatively, supply ip and port."}
		inputs["ip"] = object{"type": "string"}
		inputs["port"] = object{"type": "integer"}
	}
	if t == "cloudflare" {
		inputs["auth"] = object{"type": "string", "enum": []string{"1"}, "description": "API token authentication"}
	}
	return inputs
}

func interfaceProviderTypes(args object) (object, *opError) {
	category := str(args, "category")
	defs := map[string]object{}
	switch category {
	case "dns":
		for t, def := range accountDefinitions {
			if dns.IsSupportedProvider(def.native) {
				defs[t] = object{"name": def.label, "type": t, "nativeProvider": def.native, "config": accountInputs(t, def)}
			}
		}
	case "cert", "deploy":
		defs = certAccountInputSchemas(category == "deploy")
	default:
		return nil, invalid
	}
	if t := str(args, "type"); t != "" {
		d, ok := defs[t]
		if !ok {
			return nil, missing
		}
		return object{"code": 0, "data": d}, nil
	}
	ids := make([]string, 0, len(defs))
	for id := range defs {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	rows := make([]object, 0, len(ids))
	for _, id := range ids {
		d := defs[id]
		inputs, _ := d["config"].(object)
		if inputs == nil {
			inputs, _ = d["inputs"].(object)
		}
		fields := make([]string, 0, len(inputs))
		for f := range inputs {
			fields = append(fields, f)
		}
		slices.Sort(fields)
		rows = append(rows, object{"type": id, "name": d["name"], "fields": fields})
	}
	return object{"code": 0, "data": rows}, nil
}

// A client may rotate individual secrets, but may not redirect retained secrets
// to another endpoint. Endpoint moves use a newly created access record.
func mergeAccountConfig(t string, original, patch object) (object, *opError) {
	def, ok := accountDefinitions[t]
	if !ok {
		return nil, unsupported
	}
	config := make(object, len(original)+len(patch))
	for k, v := range original {
		config[k] = v
	}
	updates := object{}
	for key, v := range patch {
		switch {
		case key == "proxy" || key == "dnsManagementProxy":
			if _, duplicate := updates["dnsManagementProxy"]; duplicate {
				return nil, invalid
			}
			enabled, ok := v.(bool)
			if !ok && key == "proxy" {
				switch str(patch, key) {
				case "0":
					enabled, ok = false, true
				case "1":
					enabled, ok = true, true
				}
			}
			if !ok {
				return nil, invalid
			}
			updates["dnsManagementProxy"] = enabled
			continue
		case t == "cloudflare" && key == "auth":
			if str(patch, key) != "1" {
				return nil, unsupported
			}
			continue
		case (t == "cloudflare" && key == "email") || (t == "namesilo" && key == "username"):
			continue // not used by the provider's token API
		case t == "powerdns" && (key == "ip" || key == "port"):
			continue
		}
		native := def.fields[key]
		if native == "" {
			for _, n := range def.fields {
				if key == n {
					native = n
					break
				}
			}
		}
		if native == "" {
			return nil, invalid
		}
		if _, duplicate := updates[native]; duplicate {
			return nil, invalid
		}
		value := str(patch, key)
		if value == "" || len(value) > 16384 {
			return nil, invalid
		}
		updates[native] = value
	}
	if t == "powerdns" && (patch["ip"] != nil || patch["port"] != nil) {
		if updates["serverUrl"] != nil {
			return nil, invalid
		}
		var host, port string
		if old, ok := original["serverUrl"].(string); ok {
			u, err := url.Parse(old)
			if err != nil {
				return nil, invalid
			}
			host, port = u.Hostname(), u.Port()
		}
		if _, ok := patch["ip"]; ok {
			host = str(patch, "ip")
		}
		if _, ok := patch["port"]; ok {
			port = str(patch, "port")
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || host == "" || strings.ContainsAny(host, "/@?#% \\") {
			return nil, invalid
		}
		updates["serverUrl"] = "http://" + net.JoinHostPort(strings.Trim(host, "[]"), port)
	}
	if dest, ok := updates["serverUrl"]; ok && len(original) > 0 && original["serverUrl"] != dest {
		return nil, &opError{422, "Create a new credential to change the server endpoint"}
	}
	for k, v := range updates {
		config[k] = v
	}
	if t == "goedge" && config["apiRole"] == nil {
		config["apiRole"] = "admin"
	}
	return config, nil
}
