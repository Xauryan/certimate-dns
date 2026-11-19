package dnsmanagement

import (
	"math"
	"slices"
	"strings"
)

// These are the inputs the registered management adapters encode. The account's
// current plan can have stricter limits, returned by its ZoneDetails operation.
var providerCapabilities = map[string]Capabilities{
	"aliyun": {
		Types: strings.Fields("A AAAA CNAME TXT MX NS SRV CAA ALIAS REDIRECT_URL FORWARD_URL"), PriorityTypes: []string{"MX"},
		MinTTL: 1, MaxTTL: 604800, DefaultTTL: 600, ZoneCreate: true, Line: true,
	},
	"aliyunesa": {
		Types: strings.Fields("A AAAA CNAME TXT MX NS SRV CAA"), PriorityTypes: []string{"MX"},
		MinTTL: 30, MaxTTL: 86400, DefaultTTL: 1, SpecialTTLs: []int{1}, Line: true, Description: true,
	},
	"aws": {
		Types: strings.Fields("A AAAA CNAME TXT MX NS SRV CAA PTR"), PriorityTypes: []string{"MX"},
		MinTTL: 60, MaxTTL: math.MaxInt32, DefaultTTL: 600, ZoneCreate: true,
	},
	"baiducloud": {
		Types: strings.Fields("A AAAA CNAME TXT MX NS SRV"), PriorityTypes: []string{"MX"},
		MinTTL: 1, MaxTTL: math.MaxInt32, DefaultTTL: 300, ZoneCreate: true, Line: true, Description: true,
	},
	"bt": {
		Types: strings.Fields("A AAAA CNAME NS TXT MX SRV"), PriorityTypes: []string{"MX"},
		MinTTL: 300, MaxTTL: math.MaxInt32, DefaultTTL: 600, ZoneCreate: true, Line: true, Weight: true, Description: true,
	},
	"cloudflare": {
		Types: strings.Fields("A AAAA CNAME TXT MX NS SRV CAA URI"), PriorityTypes: []string{"MX", "URI"},
		MinTTL: 30, MaxTTL: 86400, DefaultTTL: 1, SpecialTTLs: []int{1}, ZoneCreate: true, Export: true, Line: true, Description: true,
	},
	"dnsla": {
		Types: strings.Fields("A AAAA CNAME TXT NS MX SRV CAA REDIRECT_URL FORWARD_URL"), PriorityTypes: []string{"MX"},
		MinTTL: 1, MaxTTL: math.MaxInt32, DefaultTTL: 600, ZoneCreate: true, Line: true, Weight: true,
	},
	"dnsmgr": {
		Types: strings.Fields("A AAAA CNAME NS TXT MX SRV CAA REDIRECT_URL FORWARD_URL"), PriorityTypes: []string{"MX"},
		MinTTL: 1, MaxTTL: math.MaxInt32, DefaultTTL: 600, Line: true, Weight: true, Description: true,
	},
	"dynv6": {
		Types: strings.Fields("A AAAA CNAME TXT SPF MX SRV CAA"), PriorityTypes: []string{"MX"},
		MinTTL: 600, MaxTTL: 600, DefaultTTL: 600,
	},
	"goedge": {
		Types: strings.Fields("A AAAA CNAME NS TXT MX SRV CAA"), PriorityTypes: []string{"MX"},
		MinTTL: 1, MaxTTL: math.MaxInt32, DefaultTTL: 600, ZoneCreate: true, Line: true, Weight: true, Description: true,
	},
	"henet": {
		Types: strings.Fields("A AAAA CNAME ALIAS TXT MX NS CAA SRV PTR"), PriorityTypes: []string{"MX"},
		MinTTL: 300, MaxTTL: math.MaxInt32, DefaultTTL: 600,
	},
	"huaweicloud": {
		Types: strings.Fields("A AAAA CNAME TXT MX NS SRV CAA"), PriorityTypes: []string{"MX"},
		MinTTL: 1, MaxTTL: math.MaxInt32, DefaultTTL: 600, ZoneCreate: true, Line: true, Weight: true, Description: true,
	},
	"jdcloud": {
		Types: strings.Fields("A AAAA CNAME TXT MX NS SRV CAA REDIRECT_URL FORWARD_URL EXPLICIT_URL IMPLICIT_URL"), PriorityTypes: []string{"MX"},
		MinTTL: 1, MaxTTL: math.MaxInt32, DefaultTTL: 600, ZoneCreate: true, Line: true, Weight: true,
	},
	"namesilo": {
		Types: strings.Fields("A AAAA CNAME TXT MX SRV CAA"), PriorityTypes: []string{"MX"},
		MinTTL: 3600, MaxTTL: 2592000, DefaultTTL: 3600,
	},
	"powerdns": {
		Types: strings.Fields("A AAAA CNAME ALIAS NS PTR TXT MX SRV CAA"), PriorityTypes: []string{"MX"},
		MinTTL: 1, MaxTTL: math.MaxInt32, DefaultTTL: 600, ZoneCreate: true, Description: true,
	},
	"qingcloud": {
		Types: strings.Fields("A AAAA CNAME TXT NS MX PTR"), PriorityTypes: []string{"MX"},
		MinTTL: 60, MaxTTL: 86400, DefaultTTL: 600, ZoneCreate: true, Line: true, Weight: true,
	},
	"spaceship": {
		Types: strings.Fields("A AAAA CNAME TXT NS MX CAA SRV PTR ALIAS"), PriorityTypes: []string{"MX"},
		MinTTL: 60, MaxTTL: 3600, DefaultTTL: 600,
	},
	"technitiumdns": {
		Types: strings.Fields("A AAAA CNAME NS TXT MX SRV PTR CAA ANAME DNAME APP"), PriorityTypes: []string{"MX"},
		MinTTL: 1, MaxTTL: math.MaxInt32, DefaultTTL: 600, ZoneCreate: true, Description: true,
	},
	"tencentcloud": {
		Types: strings.Fields("A AAAA CNAME TXT MX NS SRV CAA REDIRECT_URL FORWARD_URL"), PriorityTypes: []string{"MX"},
		MinTTL: 1, MaxTTL: 604800, DefaultTTL: 600, ZoneCreate: true, Line: true, Weight: true, Description: true,
	},
	"tencenteo": {
		Types: strings.Fields("A AAAA CNAME TXT MX NS SRV CAA"), PriorityTypes: []string{"MX"},
		MinTTL: 60, MaxTTL: 86400, DefaultTTL: 300, Line: true, Weight: true,
	},
	"volcengine": {
		Types: strings.Fields("A AAAA CNAME TXT MX NS SRV CAA"), PriorityTypes: []string{"MX"},
		MinTTL: 1, MaxTTL: 86400, DefaultTTL: 600, ZoneCreate: true, Line: true, Weight: true, Description: true,
	},
	"westcn": {
		Types: strings.Fields("A AAAA CNAME TXT NS MX SRV CAA"), PriorityTypes: []string{"MX"},
		MinTTL: 1, MaxTTL: math.MaxInt32, DefaultTTL: 600, Line: true,
	},
}

func ProviderCapabilities(provider string) (Capabilities, bool) {
	c, ok := providerCapabilities[provider]
	c.Types = slices.Clone(c.Types)
	c.PriorityTypes = slices.Clone(c.PriorityTypes)
	c.SpecialTTLs = slices.Clone(c.SpecialTTLs)
	return c, ok
}
