# DNSMgr 功能对照与验收

本文对照 DNSMgr 固定提交 `e0997e98ce348e9771256470bb3cb6820716a903` 和独立 Certimate DNS 的代码。初次核对的 Certimate 提交为 `a67b65af0ec6bbc641f226de66113e952ae34a1b`。该提交开放了三家服务商的 Zone 列表和基础记录管理。后面的表格以这个可复查的提交为基线。逐条 HTTP 路由、控制器分派、CLI、MCP 动作及数据库表见[入口索引](dnsmgr-entrypoints.zh-CN.md)。[DNSMgr 源码](https://github.com/netcccyun/dnsmgr/tree/e0997e98ce348e9771256470bb3cb6820716a903) · [Certimate DNS 源码快照](https://github.com/Xauryan/certimate-dns/tree/a67b65af0ec6bbc641f226de66113e952ae34a1b)

| 上游对象 | 固定版本数量 | 在哪里核对 |
| --- | ---: | --- |
| DNS 管理驱动 | 22 | `app/lib/DnsHelper.php` 的注册项和 `app/lib/dns/*.php` 一一对应 |
| 证书签发渠道 | 8 个可选，9 份驱动文件 | `CertHelper::$cert_config` 和 `app/lib/cert/` 相差未注册的火山引擎文件 |
| 证书部署驱动 | 51 | `DeployHelper::$deploy_config` 和 `app/lib/deploy/`。单个云厂商驱动可含多个产品 |
| 控制器与 HTTP 路由 | 13 个控制器，150 条路由 | `route/app.php` 显式声明，包括独立签名 API 的 10 条路由 |
| MCP | 5 份工具定义，28 个工具，124 个动作 | `app/lib/mcp/tools/` 的具名工具及各自的 `actions` |
| CLI 与数据 | 3 个命令，17 张表 | `config/console.php`、`app/sql/install.sql` |

**状态口径。** “有入口”表示源码已将业务操作接入运行路径。“部分”只覆盖该行写明的子集。“缺项”表示核对的提交没有对应产品入口。“上游未开放”标记固定版本自身的差异。上线、真实服务商写入、签发、部署与消息送达各需自己的验收结果。本表没有使用真实凭据运行这些操作。

## 产品能力

| 能力 | DNSMgr 的操作与数据 | 基线中的 Certimate 路径、状态及待核对行为 |
| --- | --- | --- |
| 多服务商授权 | DNS 账号新增、编辑、验证、删除，显示类型、名称、备注和绑定域名数量 | **部分**。`ui/src/pages/accesses/` 和 `internal/repository/access.go` 管理既有授权。基础 DNS 路由按 access ID 和 provider 取凭据。DNS 专属账号校验、禁用和绑定依赖检查尚需覆盖。 |
| 域名目录 | 从服务商发现域名，按账号导入本地目录、创建远端域名、分页筛选、批量修改备注/通知/删除、分类与别名 | **部分**。`internal/rest/handlers/dns.go` 枚举远端 Zone，各家分页。该提交缺本地选管目录、分类、远端建域和批处理。域名注册日期、到期日期和证书有效期是独立数据。 |
| 基础记录 | 按关键词、主机名、值、类型、线路、状态查询，详情、增删改，支持根域和通配符 | **部分**。三家服务商支持分页、名称查找和创建 A、AAAA、CNAME、TXT。PATCH 修改值和 TTL。记录类型、优先级、线路、状态、标签、备注和代理须按驱动逐项核对。见 `internal/rest/handlers/dns.go`、`pkg/core/dnsmanagement/types.go` 和 `ui/src/pages/dns/DNSManager.tsx`。 |
| DNS 服务商扩展 | 记录备注、启停、URL 转发、ALIAS、MX/SRV/CAA、记录分组、线路、动态最小 TTL、记录日志。阿里云另有权重子域配置，DNSPod 另有域名别名 | **缺项或部分字段可读**。在列表显示代理状态、线路或保留原有设置，仅能证明读取或保留。基线无独立写入口修改分组、权重、域名别名或切换记录状态。 |
| 批量、导入与导出 | 单域/跨域批量新增和编辑值/线路，批量启停、删除、改组和改备注。智能粘贴解析和预览。Excel 导出及 .xls/.xlsx 首表导入、逐行校验与结果 | **部分**。`pkg/sdk3rd/cloudflare/dns.go` 导出整个 Cloudflare Zone 的 BIND 文本。该提交缺三家统一批量服务、Excel 往返、跨域匹配和逐行回执。 |
| 解析检查 | 检测某条解析是否生效，跨域搜索、查询每域可用线路与最小 TTL | **缺项**。有效的上游检测入口是 `Domain::record_check`。`/domain/dnscheck` 虽有路由，固定版本没有同名方法。 |
| 域名到期 | WHOIS 查注册/到期日，失败状态、定期刷新、按距到期天数发送提醒 | **缺项**。`internal/certificate/service.go` 的证书过期管理处理 X.509 有效期。域名日期和通知的上游实现在 `ExpireNoticeService.php` 和 `common.php::getDomainDate`。 |
| Cloudflare for SaaS | Custom Hostnames 列表、增改删、刷新验证、验证记录目标、批量增改删、fallback origin 获取/设置/删除、DCV delegation UUID、默认线路 | **缺项**。基线的 `pkg/sdk3rd/cloudflare/api_customcertificate_*.go` 负责自定义证书的部署。该提交没有 Custom Hostnames 管理入口。 |
| Cloudflare Tunnel | 账号查找、Tunnel 创建/删除/令牌、公共主机名 ingress 与配套 CNAME、CIDR 和 hostname routes | **缺项**。上游 `app/service/CloudflareEnhanceService.php` 分开处理 zone ID 与 account ID，还检查要删除的 CNAME 是否匹配该 Tunnel。 |
| 容灾 | Ping、TCP、HTTP(S) 探测，连续失败和恢复计数、主备值切换、启停解析、条件开启解析、暂停/启用任务、日志和心跳 | **缺项**。基线的工作流 Monitor 节点用于证书监控。DNS 健康探测和记录切换需由任务调度、持久状态、服务商变更和通知共同验证。 |
| 定时切换 | 指定时刻或按天/周/月运行，支持改值、启用、暂停、删除，维护下次执行时间、批量启停/删除 | **缺项**。`internal/scheduler/` 已调度证书工作流。DNS 记录定时操作对应上游 `ScheduleService.php`。 |
| CDN 优选 IP | 定时与手工触发，选择数据源和 CDN，按 IPv4/IPv6、运营商线路与数量同步记录、查看最近状态和许可额度 | **缺项**。上游 `OptimizeService.php` 处理默认/电信/联通/移动线路及增改删。页面列 Cloudflare、CloudFront 和 EdgeOne，WeTest 后端还有 Gcore 分支。不同数据源的地址族和额度能力有差异。 |
| 证书账户、申请和续期 | 账户配置及检查、自动或上传已有证书、SAN/通配符、RSA/ECC、DNS 验证、签发、吊销、续期、订单重置与过程日志 | **部分**。已有 `internal/certacme/`、`internal/workflow/engine/executor_bizapply.go`、`executor_bizupload.go`、工作流记录及下载/吊销 API。DNSMgr 非 ACME 免费证书申购、订单状态/批量重置和外部订单 API 需单列。 |
| 验证委派 | 管理用于证书验证的域名与 CNAME 映射，生成目标、检查委派、自动添加/回收挑战记录 | **部分**。`internal/certacme/client_obtain.go` 可配置是否跟随 CNAME。基线没有 DNSMgr 的本地委派条目管理和检查页面。DNS-01 并发、清理、服务商可见性需各自验证。 |
| 证书下载和部署 | 下载证书链、私钥及 PFX，手工或自动部署、暂停/启用、改绑证书、重试与过程日志 | **部分**。`internal/certificate/service.go` 提供 PEM/PFX 下载，`internal/certmgmt/deployers/` 接入工作流。51 项上游部署驱动及对应范围见下表。订单/任务 ID 和批量操作的数据模型不同。 |
| 通知 | 告警、恢复、签发、部署和域名到期事件。SMTP、SendCloud、阿里云邮件、微信公众号模板、Telegram、QQ、钉钉、飞书、企业微信、自定义 Webhook，含测试发送 | **部分**。`pkg/core/notifier/providers/` 提供 email、telegrambot、dingtalkbot、larkbot、wecombot、webhook 等，`internal/rest/handlers/notifications.go` 提供测试入口。还需逐事件验证收件人、模板和送达。SendCloud/阿里云邮件 API、微信公众号模板、QQ 签名回调与绑定未在该提交接入。 |
| 用户及域名权限 | 管理员、普通用户与单域登录者，用户增改删、停用、分配域名、API 开关/密钥；列表、日志、详情、修改受权限约束 | **缺项**。基线的 `internal/rest/routes/routes.go` 给应用路由注册 `RequireSuperuserAuth`。管理员能够管理该实例。普通用户、域名清单、单域访问及委派凭据缺独立入口。 |
| 登录与安全设置 | 密码、验证码、失败限制、TOTP 生成/绑定/关闭及登录挑战、退出、密码修改、CLI 重置；域名单独快捷登录链接 | **部分**。`ui/src/repository/admin.ts` 和设置页支持管理员密码登录/修改。尚缺 DNSMgr 的图形验证码、按域快捷登录、普通用户 TOTP 流程及其重置。核对每个入口要区分普通用户、域名链接、机器调用和管理员。 |
| 外部 HTTP API | 10 条签名 POST，包含域名列表/详情和登录链接、记录列表/新增/更新/删除/启停/备注/批量、证书订单详情 | **缺兼容层**。基线有应用自己的 REST API。原调用方还依赖用户 API 开关、签名、时间窗口、请求字段、响应及域名权限。能从浏览器调用 REST 不能推导旧 IDC 客户端可用。 |
| MCP | JSON-RPC 初始化、版本协商、通知与批请求、工具枚举、按动作检查权限、控制器调用、来源检查 | **缺项**。参考工具按域名、记录、Cloudflare、任务、证书分组，所有 124 个动作见入口索引。 |
| 管理与运维 | 首页统计、主题、清缓存、密码与登录设置、日志筛选、代理配置与测试、cron 心跳/外部触发、安装和在线更新 | **部分**。Certimate 使用单二进制、嵌入 UI、PocketBase 迁移，有 dashboard、外观、诊断和持久化设置。DNSMgr 的管理日志范围、代理测试、cron 调用、PHP/MySQL 安装及在线更新为独立操作。 |
| 迁移 | DNSMgr 以 17 张表维护授权、域名、用户、记录相关元数据、任务、证书及依赖 | **缺项**。Certimate 原生 PocketBase 升级与从 DNSMgr 导入是两个流程。跨系统迁移需逐项验证原始 ID 关系、授权/密钥处理、重复导入和任务启用状态。 |

## DNS 管理驱动

下表的扩展取自 DNSMgr 的每家驱动配置。它列出上游标注的可选项，公用接口还包含验证账号、分页列域、按主机名查记录、详情、增改删、线路、最小 TTL。各驱动会按服务商能力返回数据或报告不支持。Certimate 的 DNS-01 列给出签发时处理 TXT 挑战的独立模块。管理列仅统计由服务端路由分派、管理 UI 能选择的驱动。[DNSMgr 注册表](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/DnsHelper.php) · [接口定义](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/DnsInterface.php)

| 上游驱动 | 上游登记的可选行为 | Certimate DNS-01 目录 | 基线 DNS 管理 |
| --- | --- | --- | --- |
| [阿里云（aliyun）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/aliyun.php) | 独立备注、启停、转发、服务商日志、建域、排序、ALIAS、记录分组、子域名权重管理 | [aliyun](../pkg/core/certifier/challengers/dns01/aliyun/) | 基础读写 |
| [腾讯云（dnspod）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/dnspod.php) | 独立备注、启停、转发、服务商日志、记录权重、建域、排序、记录分组、域名别名 | [tencentcloud](../pkg/core/certifier/challengers/dns01/tencentcloud/) | 基础读写，使用腾讯云 API |
| [华为云（huawei）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/huawei.php) | 随记录写备注、启停、记录权重、建域、排序 | [huaweicloud](../pkg/core/certifier/challengers/dns01/huaweicloud/) | 缺项 |
| [百度云（baidu）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/baidu.php) | 随记录写备注、建域、客户端分页 | [baiducloud](../pkg/core/certifier/challengers/dns01/baiducloud/) | 缺项 |
| [西部数码（west）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/west.php) | 启停 | [westcn](../pkg/core/certifier/challengers/dns01/westcn/) | 缺项 |
| [火山引擎（huoshan）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/huoshan.php) | 随记录写备注、启停、记录权重、建域 | [volcengine](../pkg/core/certifier/challengers/dns01/volcengine/) | 缺项 |
| [京东云（jdcloud）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/jdcloud.php) | 启停、转发、记录权重、建域 | [jdcloud](../pkg/core/certifier/challengers/dns01/jdcloud/) | 缺项 |
| [DNSLA（dnsla）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/dnsla.php) | 启停、转发、记录权重、建域 | [dnsla](../pkg/core/certifier/challengers/dns01/dnsla/) | 缺项 |
| [青云（qingcloud）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/qingcloud.php) | 启停、记录权重 | [qingcloud](../pkg/core/certifier/challengers/dns01/qingcloud/) | 缺项 |
| [宝塔域名（bt）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/bt.php) | 随记录写备注、启停、记录权重、建域 | 无专用模块 | 缺项 |
| [Cloudflare（cloudflare）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/cloudflare.php) | 随记录写备注、启停、建域、排序 | [cloudflare](../pkg/core/certifier/challengers/dns01/cloudflare/) | 基础读写、BIND 导出 |
| [AWS Route 53（aws）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/aws.php) | 建域、客户端分页 | [aws-route53](../pkg/core/certifier/challengers/dns01/aws-route53/) | 缺项 |
| [NameSilo（namesilo）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/namesilo.php) | 客户端分页 | [namesilo](../pkg/core/certifier/challengers/dns01/namesilo/) | 缺项 |
| [HE DNS（henet）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/henet.php) | 客户端分页、ALIAS | 无专用模块 | 缺项 |
| [Spaceship（spaceship）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/spaceship.php) | 转发、ALIAS | [spaceship](../pkg/core/certifier/challengers/dns01/spaceship/) | 缺项 |
| [PowerDNS（powerdns）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/powerdns.php) | 随记录写备注、启停、建域、客户端分页、ALIAS | [powerdns](../pkg/core/certifier/challengers/dns01/powerdns/) | 缺项 |
| [Technitium（technitium）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/technitium.php) | 随记录写备注、启停、建域、客户端分页 | [technitiumdns](../pkg/core/certifier/challengers/dns01/technitiumdns/) | 缺项 |
| [阿里云ESA（aliyunesa）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/aliyunesa.php) | 随记录写备注 | [aliyun-esa](../pkg/core/certifier/challengers/dns01/aliyun-esa/) | 缺项 |
| [腾讯云EO（tencenteo）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/tencenteo.php) | 启停、记录权重、排序 | [tencentcloud-eo](../pkg/core/certifier/challengers/dns01/tencentcloud-eo/) | 缺项 |
| [同系统对接（dnsmgr）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/dnsmgr.php) | 随记录写备注、启停、转发、记录权重 | 无专用模块 | 缺项 |
| [GoEdge智能DNS（goedge）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/goedge.php) | 随记录写备注、启停、记录权重、建域 | 无专用模块 | 缺项 |
| [dynv6（dynv6）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/dynv6.php) | 注册表未标注可选项 | [dynv6](../pkg/core/certifier/challengers/dns01/dynv6/) | 缺项 |

Cloudflare 将代理状态放在 `Line`，另外通过重命名记录模拟暂停。DNSPod 的域名别名和部分驱动的 ALIAS 记录分别操作域名和资源记录。对照测试应分别断言。

## 证书签发与部署

DNSMgr 注册的 8 个签发渠道中有 5 个属于 ACME。Certimate 在签发客户端选 CA，在另一份注册表中选择 DNS-01 服务商。云证书仓库上传和部署也有自己的注册表。[DNSMgr 渠道注册表](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/CertHelper.php) · [Certimate CA 选择](../internal/certacme/ca.go) · [Certimate EAB](../internal/certacme/eab.go)

| DNSMgr 驱动 | Certimate 基线 |
| --- | --- |
| [letsencrypt](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/cert/letsencrypt.php) | 有正式及 staging ACME 目录。 |
| [zerossl](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/cert/zerossl.php) | 有 ACME 目录和 EAB 获取代码。 |
| [google](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/cert/google.php) | 有 Google Trust Services ACME 目录。DNSMgr 的第三方 EAB 申请和反向代理模式需分别核对。 |
| [litessl](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/cert/litessl.php) | 有 LiteSSL ACME 目录。 |
| [customacme](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/cert/customacme.php) | 有自定义 ACME endpoint 和凭据。 |
| [tencent](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/cert/tencent.php) | 缺腾讯云免费 SSL 申购/认证订单适配。 |
| [aliyun](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/cert/aliyun.php) | 缺阿里云免费 SSL 申购/认证订单适配。 |
| [ucloud](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/cert/ucloud.php) | 缺 UCloud 免费 SSL 申购/认证订单适配。 |
| [huoshan](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/cert/huoshan.php) | 上游保留驱动文件，未列入上游可选渠道。 |

下表核对 51 个部署驱动。右列为 Certimate 已有对应产品的候选模块，按最终投递目标列举。云厂商通常有多个子产品，映射到模块后仍要核对服务版本、证书格式、选中资源、绑定/替换行为及重载结果。[DNSMgr 部署配置](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/DeployHelper.php) · [Certimate 部署工厂](../internal/certmgmt/deployers/) · [部署驱动](../pkg/core/deployer/providers/)

| DNSMgr 部署驱动 | Certimate 对应路径（相对 `pkg/core/deployer/providers/`）及差异 |
| --- | --- |
| [宝塔面板（btpanel）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/btpanel.php) | [baotapanel](../pkg/core/deployer/providers/baotapanel/)、[baotapanel-console](../pkg/core/deployer/providers/baotapanel-console/) |
| [宝塔Win极速版（btwin）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/btwin.php) | [baotapanelgo](../pkg/core/deployer/providers/baotapanelgo/)、[baotapanelgo-console](../pkg/core/deployer/providers/baotapanelgo-console/) |
| [Kangle用户（kangle）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/kangle.php) | 缺专用部署驱动。 |
| [Kangle管理员（kangleadmin）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/kangleadmin.php) | 缺专用部署驱动。 |
| [雷池WAF（safeline）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/safeline.php) | [safeline](../pkg/core/deployer/providers/safeline/) |
| [堡塔云WAF（btwaf）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/btwaf.php) | [baotawaf](../pkg/core/deployer/providers/baotawaf/)、[baotawaf-console](../pkg/core/deployer/providers/baotawaf-console/) |
| [Cdnfly（cdnfly）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/cdnfly.php) | [cdnfly](../pkg/core/deployer/providers/cdnfly/) |
| [LeCDN（lecdn）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/lecdn.php) | [lecdn](../pkg/core/deployer/providers/lecdn/) |
| [GoEdge（goedge）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/goedge.php) | [goedge](../pkg/core/deployer/providers/goedge/)、[flexcdn](../pkg/core/deployer/providers/flexcdn/) |
| [南墙WAF（uusec）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/uusec.php) | 缺专用部署驱动。 |
| [SamWaf（samwaf）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/samwaf.php) | [samwaf](../pkg/core/deployer/providers/samwaf/)、[samwaf-console](../pkg/core/deployer/providers/samwaf-console/) |
| [1Panel（opanel）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/opanel.php) | [1panel](../pkg/core/deployer/providers/1panel/)、[1panel-console](../pkg/core/deployer/providers/1panel-console/) |
| [MW面板（mwpanel）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/mwpanel.php) | 缺专用部署驱动。 |
| [AcePanel（acepanel）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/acepanel.php) | [ratpanel](../pkg/core/deployer/providers/ratpanel/)、[ratpanel-console](../pkg/core/deployer/providers/ratpanel-console/)。面板同名，3.x API 版本仍需核对。 |
| [耗子面板（ratpanel）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/ratpanel.php) | [ratpanel](../pkg/core/deployer/providers/ratpanel/)、[ratpanel-console](../pkg/core/deployer/providers/ratpanel-console/) |
| [小皮面板（xp）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/xp.php) | 缺专用部署驱动。 |
| [AMH面板（amh）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/amh.php) | 缺专用部署驱动。 |
| [CloudPanel（cloudpanel）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/cloudpanel.php) | 缺专用部署驱动。 |
| [DirectAdmin（directadmin）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/directadmin.php) | 缺专用部署驱动。 |
| [群晖面板（synology）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/synology.php) | [synologydsm](../pkg/core/deployer/providers/synologydsm/) |
| [Lucky（lucky）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/lucky.php) | 缺专用部署驱动。 |
| [飞牛OS（fnos）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/fnos.php) | 有 SSH 工作流脚本预设，缺独立飞牛 API 部署驱动。 |
| [Nginx Proxy Manager（nginxproxymanager）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/nginxproxymanager.php) | [nginxproxymanager](../pkg/core/deployer/providers/nginxproxymanager/)。仍需核对自动绑定 Proxy Host 的行为。 |
| [Proxmox VE（proxmox）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/proxmox.php) | [proxmoxve](../pkg/core/deployer/providers/proxmoxve/) |
| [K8S（k8s）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/k8s.php) | [k8s-secret](../pkg/core/deployer/providers/k8s-secret/)。上游还可修改 Ingress TLS 绑定。 |
| [阿里云（aliyun）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/aliyun.php) | [aliyun-cdn](../pkg/core/deployer/providers/aliyun-cdn/)、[aliyun-esa](../pkg/core/deployer/providers/aliyun-esa/)、[aliyun-clb](../pkg/core/deployer/providers/aliyun-clb/)、[aliyun-oss](../pkg/core/deployer/providers/aliyun-oss/)、[aliyun-waf](../pkg/core/deployer/providers/aliyun-waf/)、[aliyun-fc](../pkg/core/deployer/providers/aliyun-fc/) |
| [腾讯云（tencent）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/tencent.php) | [tencentcloud-cdn](../pkg/core/deployer/providers/tencentcloud-cdn/)、[tencentcloud-eo](../pkg/core/deployer/providers/tencentcloud-eo/)、[tencentcloud-clb](../pkg/core/deployer/providers/tencentcloud-clb/)、[tencentcloud-cos](../pkg/core/deployer/providers/tencentcloud-cos/)、[tencentcloud-scf](../pkg/core/deployer/providers/tencentcloud-scf/)。TKE 的订单/资源绑定需另核。 |
| [华为云（huawei）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/huawei.php) | [huaweicloud-cdn](../pkg/core/deployer/providers/huaweicloud-cdn/)、[huaweicloud-elb](../pkg/core/deployer/providers/huaweicloud-elb/)、[huaweicloud-waf](../pkg/core/deployer/providers/huaweicloud-waf/) |
| [UCloud（ucloud）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/ucloud.php) | [ucloud-ucdn](../pkg/core/deployer/providers/ucloud-ucdn/) |
| [七牛云（qiniu）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/qiniu.php) | [qiniu-cdn](../pkg/core/deployer/providers/qiniu-cdn/)、[qiniu-kodo](../pkg/core/deployer/providers/qiniu-kodo/) |
| [多吉云（doge）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/doge.php) | [dogecloud-cdn](../pkg/core/deployer/providers/dogecloud-cdn/) |
| [AxisNow（axisnow）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/axisnow.php) | [axisnow](../pkg/core/deployer/providers/axisnow/) |
| [又拍云（upyun）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/upyun.php) | [upyun-cdn](../pkg/core/deployer/providers/upyun-cdn/) |
| [百度云（baidu）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/baidu.php) | [baiducloud-cdn](../pkg/core/deployer/providers/baiducloud-cdn/)、[baiducloud-blb](../pkg/core/deployer/providers/baiducloud-blb/) |
| [金山云（ksyun）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/ksyun.php) | [ksyun-cdn](../pkg/core/deployer/providers/ksyun-cdn/) |
| [火山引擎（huoshan）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/huoshan.php) | [volcengine-cdn](../pkg/core/deployer/providers/volcengine-cdn/)、[volcengine-clb](../pkg/core/deployer/providers/volcengine-clb/)、[volcengine-tos](../pkg/core/deployer/providers/volcengine-tos/)、[volcengine-live](../pkg/core/deployer/providers/volcengine-live/)、[volcengine-imagex](../pkg/core/deployer/providers/volcengine-imagex/) |
| [西部数码（west）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/west.php) | 缺专用部署驱动。 |
| [网宿科技（wangsu）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/wangsu.php) | [wangsu-cdn](../pkg/core/deployer/providers/wangsu-cdn/)、[wangsu-cdnpro](../pkg/core/deployer/providers/wangsu-cdnpro/)、[wangsu-certificate](../pkg/core/deployer/providers/wangsu-certificate/) |
| [白山云（baishan）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/baishan.php) | [baishan-cdn](../pkg/core/deployer/providers/baishan-cdn/) |
| [天翼云（ctyun）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/ctyun.php) | [ctcccloud-cdn](../pkg/core/deployer/providers/ctcccloud-cdn/)、[ctcccloud-ao](../pkg/core/deployer/providers/ctcccloud-ao/) |
| [括彩云（kuocai）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/kuocai.php) | 缺专用部署驱动。 |
| [全栈云（qzyun）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/qzyun.php) | 缺专用部署驱动。 |
| [雨云（rainyun）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/rainyun.php) | [rainyun-sslcenter](../pkg/core/deployer/providers/rainyun-sslcenter/)、[rainyun-rcdn](../pkg/core/deployer/providers/rainyun-rcdn/) |
| [uniCloud（unicloud）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/unicloud.php) | [unicloud-webhost](../pkg/core/deployer/providers/unicloud-webhost/) |
| [AWS（aws）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/aws.php) | [aws-cloudfront](../pkg/core/deployer/providers/aws-cloudfront/)、[aws-acm](../pkg/core/deployer/providers/aws-acm/) |
| [Gcore（gcore）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/gcore.php) | [gcore-cdn](../pkg/core/deployer/providers/gcore-cdn/) |
| [Cachefly（cachefly）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/cachefly.php) | [cachefly](../pkg/core/deployer/providers/cachefly/) |
| [SSH服务器（ssh）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/ssh.php) | [ssh](../pkg/core/deployer/providers/ssh/) |
| [FTP服务器（ftp）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/ftp.php) | [ftp](../pkg/core/deployer/providers/ftp/) |
| [S3存储（s3storage）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/s3storage.php) | [s3](../pkg/core/deployer/providers/s3/) |
| [复制到本机（local）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/local.php) | [local](../pkg/core/deployer/providers/local/) |

## 核验记录

- 核对了上游固定提交的注册表、驱动文件、路由与目标方法。150 条路由中的 `/domain/dnscheck` 缺目标方法。`Index::doc` 有方法、无显式路由。`Index::test` 方法体为空。计数保留了这些差异。
- 基础 DNS 管理直接证据来自 [API 处理器](../internal/rest/handlers/dns.go)、[管理页面](../ui/src/pages/dns/DNSManager.tsx)、[Cloudflare HTTP 模拟用例](../pkg/sdk3rd/cloudflare/dns_test.go) 和[浏览器测试源码](../tests/browser/dns-records.cjs)。模拟响应与浏览器拦截能验证请求、表单或结果展示。真实账号的权限、配额、线路行为和公网最终生效需要单独记录。
- 签发与部署的映射依据为注册工厂与供应商实现。每个部署目标的真实验收至少要能确定证书投递到哪个资源、对外实际呈现的证书，以及服务商返回成功后的最终状态。
