package dnsmanagement

import (
	"time"

	"github.com/certimate-go/certimate/internal/dnsdrivers/dnsutil"
	"github.com/pocketbase/pocketbase/core"

	aliyunesa "github.com/certimate-go/certimate/internal/dnsdrivers/aliyunesa"
	aws "github.com/certimate-go/certimate/internal/dnsdrivers/aws"
	baidu "github.com/certimate-go/certimate/internal/dnsdrivers/baidu"
	bt "github.com/certimate-go/certimate/internal/dnsdrivers/bt"
	dnsla "github.com/certimate-go/certimate/internal/dnsdrivers/dnsla"
	dnsmgr "github.com/certimate-go/certimate/internal/dnsdrivers/dnsmgr"
	dynv6 "github.com/certimate-go/certimate/internal/dnsdrivers/dynv6"
	goedge "github.com/certimate-go/certimate/internal/dnsdrivers/goedge"
	henet "github.com/certimate-go/certimate/internal/dnsdrivers/henet"
	huawei "github.com/certimate-go/certimate/internal/dnsdrivers/huawei"
	huoshan "github.com/certimate-go/certimate/internal/dnsdrivers/huoshan"
	jdcloud "github.com/certimate-go/certimate/internal/dnsdrivers/jdcloud"
	namesilo "github.com/certimate-go/certimate/internal/dnsdrivers/namesilo"
	powerdns "github.com/certimate-go/certimate/internal/dnsdrivers/powerdns"
	qingcloud "github.com/certimate-go/certimate/internal/dnsdrivers/qingcloud"
	spaceship "github.com/certimate-go/certimate/internal/dnsdrivers/spaceship"
	technitium "github.com/certimate-go/certimate/internal/dnsdrivers/technitium"
	tencenteo "github.com/certimate-go/certimate/internal/dnsdrivers/tencenteo"
	west "github.com/certimate-go/certimate/internal/dnsdrivers/west"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	cf "github.com/certimate-go/certimate/pkg/sdk3rd/cloudflare"
)

// Constructors return the native vendor implementation so optional capabilities
// such as record history remain discoverable by the calling service.
var additionalProviders = map[string]func(*domain.Access) (dns.Provider, error){
	"aliyunesa":     aliyunesa.New,
	"aws":           aws.New,
	"baiducloud":    baidu.New,
	"bt":            bt.New,
	"dnsla":         dnsla.New,
	"dnsmgr":        dnsmgr.New,
	"dynv6":         dynv6.New,
	"goedge":        goedge.New,
	"henet":         henet.New,
	"huaweicloud":   huawei.New,
	"volcengine":    huoshan.New,
	"jdcloud":       jdcloud.New,
	"namesilo":      namesilo.New,
	"powerdns":      powerdns.New,
	"qingcloud":     qingcloud.New,
	"spaceship":     spaceship.New,
	"technitiumdns": technitium.New,
	"tencenteo":     tencenteo.New,
	"westcn":        west.New,
}

// Open binds a management operation to one existing Certimate credential.
// Cloudflare can use a separate, less privileged token for listing zones.
func Open(a *domain.Access, zoneDiscovery bool, apps ...core.App) (dns.Provider, error) {
	var app core.App
	if len(apps) > 0 {
		app = apps[0]
	}
	a, err := WithAccountTransport(app, a)
	if err != nil {
		return nil, err
	}
	if newProvider, ok := additionalProviders[a.Provider]; ok {
		return newProvider(a)
	}
	switch a.Provider {
	case "aliyun":
		return NewAliyun(a)
	case "tencentcloud":
		return NewTencent(a)
	case "cloudflare":
		var auth cf.OptionsFunc
		switch accountField(a, "authMethod") {
		case "globalapikey":
			auth = cf.WithGlobalAPIKey(accountField(a, "email"), accountField(a, "apiKey"))
		case "", "apitoken":
			token := accountField(a, "apiToken")
			if alternate := accountField(a, "apiTokenForZone"); zoneDiscovery && alternate != "" {
				token = alternate
			}
			auth = cf.WithApiToken(token)
		default:
			return nil, domain.ErrInvalidParams
		}
		c, err := cf.NewClient(auth, cf.WithAccountID(accountField(a, "accountId")), cf.WithDNSTransport(dnsutil.TransportFor(a)))
		if err != nil {
			return nil, domain.NewError(400, "invalid Cloudflare credential")
		}
		return c.SetTimeout(25 * time.Second), nil
	default:
		return nil, domain.ErrInvalidParams
	}
}
