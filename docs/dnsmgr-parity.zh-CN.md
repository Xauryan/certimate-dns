# DNSMgr 功能对照与验收

本文对照 DNSMgr 固定提交 `e0997e98ce348e9771256470bb3cb6820716a903` 和独立 Certimate DNS 的代码。初次核对的 Certimate 提交为 `a67b65af0ec6bbc641f226de66113e952ae34a1b`。该提交开放了三家服务商的 Zone 列表和基础记录管理。当前分支的入口和可复验范围列在首表之后。产品能力快照保留这个提交作为开发起点。逐驱动表给出当前分支的实现。逐条 HTTP 路由、控制器分派、CLI、MCP 动作及数据库表见[入口索引](dnsmgr-entrypoints.zh-CN.md)。[DNSMgr 源码](https://github.com/netcccyun/dnsmgr/tree/e0997e98ce348e9771256470bb3cb6820716a903) · [Certimate DNS 源码快照](https://github.com/Xauryan/certimate-dns/tree/a67b65af0ec6bbc641f226de66113e952ae34a1b)

| 上游对象 | 固定版本数量 | 在哪里核对 |
| --- | ---: | --- |
| DNS 管理驱动 | 22 | `app/lib/DnsHelper.php` 的注册项和 `app/lib/dns/*.php` 一一对应 |
| 证书签发渠道 | 8 个可选，9 份驱动文件 | `CertHelper::$cert_config` 和 `app/lib/cert/` 相差未注册的火山引擎文件 |
| 证书部署驱动 | 51 | `DeployHelper::$deploy_config` 和 `app/lib/deploy/`。单个云厂商驱动可含多个产品 |
| 控制器与 HTTP 路由 | 13 个控制器，150 条路由 | `route/app.php` 显式声明，包括独立签名 API 的 10 条路由 |
| MCP | 5 份工具定义，28 个工具，124 个动作 | `app/lib/mcp/tools/` 的具名工具及各自的 `actions` |
| CLI 与数据 | 3 个命令，17 张表 | `config/console.php`、`app/sql/install.sql` |

**状态口径。** “有入口”表示源码已将业务操作接入运行路径。“部分”只覆盖该行写明的子集。“缺项”表示核对的提交没有对应产品入口。“上游未开放”标记固定版本自身的差异。上线、真实服务商写入、签发、部署与消息送达各需自己的验收结果。本表没有使用真实凭据运行这些操作。

## 当前分支的实现与验收

下表按固定上游的控制器及后台服务查找本分支的运行入口。下文「接入前快照」保留了开发起点，便于复查原有能力。完整程序的验收要使用同一次构建的可执行文件和 UI。进程测试命令为 `python3 tests/integration/acceptance.py --binary ./dist/certimate`。[测试步骤与断言](../tests/integration/README.zh-CN.md) · [主程序注册入口](../internal/rest/routes/dns.go)

| DNSMgr 入口 | 本分支的业务入口 | 已覆盖的范围与待验项 |
| --- | --- | --- |
| Domain · 账号、域名、分类、到期 | [账号与域名目录](../internal/dnscatalog/)、[注册日期刷新](../internal/dnscatalog/registration.go) | 从服务商发现、按选择导入或同步域名、启停账号、按分类筛选、批量调整目录信息、按域关联原工作流。自动刷新注册日期时先查 RDAP，缺少可用的安全 RDAP 记录时回退到 WHOIS。域名注册日期与 X.509 有效期分别保存。进程测试覆盖两个账号出现同一服务商 Zone ID 的情况；实际注册局数据和提醒送达需单独验收。 |
| Domain · 记录及服务商扩展 | [服务商工厂](../internal/dnsmanagement/factory.go)、[各驱动类型和 TTL](../pkg/core/dnsmanagement/provider_capabilities.go)、[高级路由](../internal/dnsadvanced/routes.go) | 上游 22 个 DNS 驱动均有 Certimate 注册项。接口按驱动选择记录类型、线路、权重、备注、代理、分组及启停能力。回环进程用例覆盖 PowerDNS 的 TXT 增删改查和 MX/TXT 批量计划，其他驱动的协议用例见各实现目录。共享 RRset 的 TTL、备注和权重受服务商粒度限制。HE.net 动态更新记录只读，Technitium 排除根区 `.`，未知类型只读。Spaceship 实现 ALIAS；其上游配置虽列出转发，驱动本身缺少相应原生记录编码。 |
| Domain · 批量、智能解析、导入导出、记录日志 | [批量 API 与逐条结果](../internal/dnsbatch/)、[文件与预览界面](../ui/src/pages/dnsbatch/) | 单域或同账号多域可预览后提交变更，区分服务商操作日志与本地执行历史。文件导入读取 .xls/.xlsx 首表，可导出 .xlsx。原生 `certimate.dns.zone` v1 归档另存类型、分组与来源标识。每个预览计划最多 200 项。要验证某个记录类型或元数据是否能往返，需同时检查工作簿列、批量计划和目标适配器。 |
| Cloudflare · SaaS 与 Tunnel | [管理 API](../internal/cfmanagement/)、[Cloudflare 管理页](../ui/src/pages/cfmanagement/)、[SDK](../pkg/sdk3rd/cloudflare/) | Custom Hostnames、验证记录、fallback、DCV，以及 Tunnel 的连接信息、公共主机名与路由均有对应源码。删除和回读涉及 Zone、Cloudflare 账号及 Tunnel 三种身份。真实 Cloudflare 套餐、账户权限与边缘生效仍待验。 |
| Dmonitor、Schedule · 容灾与定时变更 | [任务及心跳 API](../internal/dnsautomation/api.go)、[任务执行测试](../internal/dnsautomation/engine_test.go) | 任务保存目标与运行状态，执行前重查账号和 Zone。用例覆盖连续失败及恢复阈值、冷却、租约过期、撤销授权、读回与避免重复写。探测目标须列入管理员配置的 `CERTIMATE_DNS_PROBE_IPS` 并对应在管记录。可用协议为 Ping、HTTP、HTTPS 以及端口 80/443 的 TCP。外部公共探测节点、线路故障、长时间调度及消息送达待环境验收。 |
| Optimizeip · 数据源与优选 | [候选、配额、预览与执行](../internal/dnsoptimize/)、[优选测试](../internal/dnsoptimize/service_test.go) | 选择 CDN、地址族和线路后按预览确认变更，可保存任务和查看历史。用例覆盖候选数据、变更作用域、回读及调度持久化。各源的实时配额、可用地址族和线路效果取决于供应商。 |
| Cert · 签发、续期、验证、下载 | [商业证书订单](../internal/dnscert/)、[DNS-01 执行器](../internal/workflow/engine/executor_bizapply.go)、[证书工作流](../internal/certacme/) | 上游可选商业签发商为阿里云、腾讯云、UCloud；火山引擎在固定上游只有驱动源码。订单、域名验证、材料入库、续期和吊销有独立路径。旧图和 `providerAccessId` 按原样读取。HTTP 模拟回执、合成证书与数据库事务测试分别覆盖不同阶段；实际申购、签发、清理和吊销需按签发商验收。 |
| Cert · 部署账户、任务与处理 | [工作流部署工厂](../internal/certmgmt/deployers/)、[目标驱动](../pkg/core/deployer/providers/)、[MCP 部署任务](../internal/dnsmcp/cert_deploy.go) | 原生工作流可关联证书、调用部署器并保留运行记录。新增 DNSMgr 面板部署器与腾讯云 TKE 接入，AMH 缺少已核实的受支持认证流程，本分支未注册执行器。下文逐项列出上游 51 个驱动的代码、子产品或限制。面板版本、云产品资源绑定和热重载要按子产品核对。共享云厂商名称或已登记驱动只能定位实现。 |
| Auth、User · 用户、域名授权、登录与审计 | [成员、工作区、Zone 授权与单域链接](../internal/dnsauth/)、[登录策略和身份验证](../internal/dnsidentity/) | 跨工作区与单域授权按可见域计数、分页和校验读写。进程用例验证权限撤销对已登录成员生效，且跨账号同名域、已停账号无法产生模拟提供方调用。TOTP、密码、单域链接及会话失效有独立用例，外部身份提供方登录仍待验。 |
| Mcp 与签名 API | [协议入口](../internal/dnsmcp/routes.go)、[工具声明](../internal/dnsmcp/schema.json)、[密钥与角色测试](../internal/dnsmcp/auth_test.go) | 嵌入声明有 28 个工具、124 个动作，协议发现与实际动作执行分别核对。实际工具列表按调用角色、授权动作与 Zone 构建。10 条签名 HTTP 入口中，三类普通读取接受原版签名。六个写入口、证书私钥导出以及域名详情中申请一次性登录链接均须 v2 签名。委托密钥管理账号时，只允许探测固定服务商端点；自建 DNS 端点由本地管理员配置。详见[签名与权限](dnsmgr-interfaces.zh-CN.md)。 |
| Qqbot、System · 通知与设置 | [QQ/OIDC/登录策略](../internal/dnsidentity/)、[通知渠道与测试](../internal/notify/notifiers/)、[设置](../ui/src/pages/settings/) | SendCloud、阿里云 DirectMail、WxPusher 与原有 Certimate 渠道使用同一套授权管理。QQ 签名回调、绑定、目的地隔离和模拟回执有用例。邮件与各聊天平台的实际收件人、告警及恢复通知需逐事件验收。 |
| Index、Install、System · 首页、安装、更新及维护 | [应用入口](../main.go)、[设置与诊断](../ui/src/pages/settings/)、[数据库迁移](../migrations/) | 首次运行以 PocketBase 初始化，升级时重用原数据库，后台调度跟随主程序。管理员可保存实例 DNS 代理并测试固定目标的连通性。PHP 安装向导、PHP 缓存、在线源码替换和外部 cron 触发对应的运维流程仍有差异。[代理设置](../internal/dnsproxysettings/)本地轻量 PocketBase 进程用例验证了空库、旧库及再次打开，完整嵌入 UI 的发行二进制需运行同一验收脚本。 |
| 从 DNSMgr 迁移 | [迁移命令](../cmd/dnsmgr-migrate/)、[清单、预览与导入](../internal/dnsmigrate/) | [迁移手册](dnsmgr-migration.zh-CN.md)逐项列出 17 张来源表以及落库、暂存、仅计数的区别。本地 MariaDB 11.8.6 使用 schema 1049 和合成数据完成只读导出。映射来源账号、Zone、分类和任务，按源身份去重，服务商账号需要绑定到本机授权。关联清单供复核，证书私钥、外部订单状态、原站登录密码或权限不会随清单启用。需要用获授权的真实历史库验证部署前的映射与数量。 |

以下「接入前快照」中的「缺项」仅描述基线提交 `a67b65a`。其后的逐驱动表已更新至当前实现。

## 接入前快照 · 产品能力

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

## DNS 管理驱动逐项对照

下表的扩展取自 DNSMgr 的每家驱动配置。它列出上游标注的可选项，公用接口还包含验证账号、分页列域、按主机名查记录、详情、增改删、线路、最小 TTL。各驱动会按服务商能力返回数据或报告不支持。Certimate 的 DNS-01 列给出签发时处理 TXT 挑战的独立模块。当前管理列指向服务端实现和离线协议用例。记录编辑器按驱动公布的输入选择类型和 TTL，实际账号计划会进一步限制可写字段。[当前管理工厂](../internal/dnsmanagement/factory.go) · [类型及字段](../pkg/core/dnsmanagement/provider_capabilities.go)。[DNSMgr 注册表](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/DnsHelper.php) · [接口定义](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/DnsInterface.php)

| 上游驱动 | 上游登记的可选行为 | Certimate DNS-01 目录 | 当前管理实现与离线证据 |
| --- | --- | --- | --- |
| [阿里云（aliyun）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/aliyun.php) | 独立备注、启停、转发、服务商日志、建域、排序、ALIAS、记录分组、子域名权重管理 | [aliyun](../pkg/core/certifier/challengers/dns01/aliyun/) | [实现](../internal/dnsmanagement/aliyun.go) · [用例](../internal/dnsmanagement/groups_advanced_test.go)。资源组、分组、权重子域和操作日志。 |
| [腾讯云（dnspod）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/dnspod.php) | 独立备注、启停、转发、服务商日志、记录权重、建域、排序、记录分组、域名别名 | [tencentcloud](../pkg/core/certifier/challengers/dns01/tencentcloud/) | [实现](../internal/dnsmanagement/tencent.go) · [用例](../internal/dnsmanagement/groups_advanced_test.go)。线路、权重、记录分组、域名别名和操作日志。 |
| [华为云（huawei）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/huawei.php) | 随记录写备注、启停、记录权重、建域、排序 | [huaweicloud](../pkg/core/certifier/challengers/dns01/huaweicloud/) | [实现](../internal/dnsdrivers/huawei/huawei.go) · [用例](../internal/dnsdrivers/huawei/huawei_test.go)。按记录集操作，独立记录修改保留同组其他值。 |
| [百度云（baidu）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/baidu.php) | 随记录写备注、建域、客户端分页 | [baiducloud](../pkg/core/certifier/challengers/dns01/baiducloud/) | [实现](../internal/dnsdrivers/baidu/baidu.go) · [用例](../internal/dnsdrivers/baidu/baidu_test.go)。游标分页，建域后读回。 |
| [西部数码（west）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/west.php) | 启停 | [westcn](../pkg/core/certifier/challengers/dns01/westcn/) | [实现](../internal/dnsdrivers/west/provider.go) · [用例](../internal/dnsdrivers/west/provider_test.go)。签名表单和记录启停。 |
| [火山引擎（huoshan）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/huoshan.php) | 随记录写备注、启停、记录权重、建域 | [volcengine](../pkg/core/certifier/challengers/dns01/volcengine/) | [实现](../internal/dnsdrivers/huoshan/provider.go) · [用例](../internal/dnsdrivers/huoshan/provider_test.go)。线路、权重、备注、启停与建域。 |
| [京东云（jdcloud）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/jdcloud.php) | 启停、转发、记录权重、建域 | [jdcloud](../pkg/core/certifier/challengers/dns01/jdcloud/) | [实现](../internal/dnsdrivers/jdcloud/provider.go) · [用例](../internal/dnsdrivers/jdcloud/provider_test.go)。域内记录 ID、URL 转发、MX 优先级与建域。 |
| [DNSLA（dnsla）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/dnsla.php) | 启停、转发、记录权重、建域 | [dnsla](../pkg/core/certifier/challengers/dns01/dnsla/) | [实现](../internal/dnsdrivers/dnsla/dnsla.go) · [用例](../internal/dnsdrivers/dnsla/dnsla_test.go)。区域创建、线路、权重与逐区变更。 |
| [青云（qingcloud）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/qingcloud.php) | 启停、记录权重 | [qingcloud](../pkg/core/certifier/challengers/dns01/qingcloud/) | [实现](../internal/dnsdrivers/qingcloud/mutate.go) · [用例](../internal/dnsdrivers/qingcloud/provider_test.go)。线路、权重、建域后读回和空回执处理。 |
| [宝塔域名（bt）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/bt.php) | 随记录写备注、启停、记录权重、建域 | 无专用模块 | [实现](../internal/dnsdrivers/bt/bt.go) · [用例](../internal/dnsdrivers/bt/bt_test.go)。签名、账号 ID、建域和记录操作。 |
| [Cloudflare（cloudflare）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/cloudflare.php) | 随记录写备注、启停、建域、排序 | [cloudflare](../pkg/core/certifier/challengers/dns01/cloudflare/) | [实现](../pkg/sdk3rd/cloudflare/dns.go) · [用例](../pkg/sdk3rd/cloudflare/domain_advanced_test.go)。账号限定、Token/Global API Key、代理、备注、记录启停。 |
| [AWS Route 53（aws）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/aws.php) | 建域、客户端分页 | [aws-route53](../pkg/core/certifier/challengers/dns01/aws-route53/) | [实现](../internal/dnsdrivers/aws/aws.go) · [用例](../internal/dnsdrivers/aws/aws_test.go)。按值更新 RRset，保留其他值，受管路由类型只读。 |
| [NameSilo（namesilo）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/namesilo.php) | 客户端分页 | [namesilo](../pkg/core/certifier/challengers/dns01/namesilo/) | [实现](../internal/dnsdrivers/namesilo/provider.go) · [用例](../internal/dnsdrivers/namesilo/provider_test.go)。更新后采用服务商返回的新 ID。 |
| [HE DNS（henet）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/henet.php) | 客户端分页、ALIAS | 无专用模块 | [实现](../internal/dnsdrivers/henet/provider.go) · [用例](../internal/dnsdrivers/henet/provider_test.go)。面板登录、记录管理，动态更新记录只读。 |
| [Spaceship（spaceship）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/spaceship.php) | 转发、ALIAS | [spaceship](../pkg/core/certifier/challengers/dns01/spaceship/) | [实现](../internal/dnsdrivers/spaceship/provider.go) · [用例](../internal/dnsdrivers/spaceship/provider_test.go)。ALIAS 及同名多值合并，上游声明的 URL 转发缺少写入编码。 |
| [PowerDNS（powerdns）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/powerdns.php) | 随记录写备注、启停、建域、客户端分页、ALIAS | [powerdns](../pkg/core/certifier/challengers/dns01/powerdns/) | [实现](../internal/dnsdrivers/powerdns/powerdns.go) · [用例](../internal/dnsdrivers/powerdns/powerdns_test.go)。RRset 及同组值保护。备注和 TTL 为集合级。 |
| [Technitium（technitium）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/technitium.php) | 随记录写备注、启停、建域、客户端分页 | [technitiumdns](../pkg/core/certifier/challengers/dns01/technitiumdns/) | [实现](../internal/dnsdrivers/technitium/provider.go) · [用例](../internal/dnsdrivers/technitium/provider_test.go)。命名区域、分组内单值修改、备注和启停，根区域除外。 |
| [阿里云ESA（aliyunesa）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/aliyunesa.php) | 随记录写备注 | [aliyun-esa](../pkg/core/certifier/challengers/dns01/aliyun-esa/) | [实现](../internal/dnsdrivers/aliyunesa/aliyunesa.go) · [用例](../internal/dnsdrivers/aliyunesa/aliyunesa_test.go)。NS 接入站点、资源组、代理、备注。多地址记录受限。 |
| [腾讯云EO（tencenteo）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/tencenteo.php) | 启停、记录权重、排序 | [tencentcloud-eo](../pkg/core/certifier/challengers/dns01/tencentcloud-eo/) | [实现](../internal/dnsdrivers/tencenteo/provider.go) · [用例](../internal/dnsdrivers/tencenteo/provider_test.go)。NS 接入、国内或国际端点、启停、线路和权重。 |
| [同系统对接（dnsmgr）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/dnsmgr.php) | 随记录写备注、启停、转发、记录权重 | 无专用模块 | [实现](../internal/dnsdrivers/dnsmgr/dnsmgr.go) · [用例](../internal/dnsdrivers/dnsmgr/dnsmgr_test.go)。访问已配置的对端账号，记录读写受对端接口协议限制。 |
| [GoEdge智能DNS（goedge）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/goedge.php) | 随记录写备注、启停、记录权重、建域 | 无专用模块 | [实现](../internal/dnsdrivers/goedge/records.go) · [用例](../internal/dnsdrivers/goedge/goedge_test.go)。DNS 集群和账户范围、线路、权重与建域。 |
| [dynv6（dynv6）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/dns/dynv6.php) | 注册表未标注可选项 | [dynv6](../pkg/core/certifier/challengers/dns01/dynv6/) | [实现](../internal/dnsdrivers/dynv6/provider.go) · [用例](../internal/dnsdrivers/dynv6/provider_test.go)。域内记录操作，TTL 固定 600。 |

Cloudflare 将代理状态放在 `Line`，另外通过重命名记录模拟暂停。DNSPod 的域名别名和部分驱动的 ALIAS 记录分别操作域名和资源记录。对照测试应分别断言。

## 证书签发与部署逐项对照

DNSMgr 注册的 8 个签发渠道中有 5 个属于 ACME。Certimate 在签发客户端选 CA，在另一份注册表中选择 DNS-01 服务商。云证书仓库上传和部署也有自己的注册表。[DNSMgr 渠道注册表](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/CertHelper.php) · [Certimate CA 选择](../internal/certacme/ca.go) · [Certimate EAB](../internal/certacme/eab.go)

| DNSMgr 签发驱动 | 当前业务入口与限制 |
| --- | --- |
| [letsencrypt](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/cert/letsencrypt.php) | 正式和 staging 目录通过 ACME 工作流选择。 |
| [zerossl](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/cert/zerossl.php) | ACME 工作流支持手填 EAB 或通过 ZeroSSL 官方接口取得 EAB。[EAB 客户端](../internal/certacme/eab.go) |
| [google](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/cert/google.php) | Google Trust Services 官方 ACME 目录和手填 EAB。上游第三方 EAB 代办和反向代理模式不在该入口内。 |
| [litessl](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/cert/litessl.php) | LiteSSL ACME 目录及手填 EAB。 |
| [customacme](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/cert/customacme.php) | 管理员提供目录和可选 EAB，走原生 ACME 工作流。 |
| [tencent](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/cert/tencent.php) | 免费 DV 订单支持申请、DNS 验证、下载与吊销。[订单](../internal/dnscert/tencent.go) · [模拟生命周期](../internal/dnscert/issuer_adapters_test.go) |
| [aliyun](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/cert/aliyun.php) | 从已有额度选择空闲实例，使用联系人和实例提交申请。[订单](../internal/dnscert/aliyun.go) · [实例选择与回执用例](../internal/dnscert/issuer_adapters_test.go) |
| [ucloud](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/cert/ucloud.php) | 免费 DV 订单要求联系人字段，验证 DNS、下载签名存储对象并校验档案。[订单](../internal/dnscert/ucloud.go) · [协议与档案用例](../internal/dnscert/ucloud_test.go) |
| [huoshan](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/cert/huoshan.php) | 固定上游未列入可选渠道。分支保留适配器和离线协议用例，商业订单工厂仅开放前三家。[工厂](../internal/dnscert/order.go) · [适配器](../internal/dnscert/volcengine.go) |

下表按 51 个上游文件逐个定位 Certimate 的部署入口。带「用例」的链接给出本分支新增离线验证；其余行是原生模块的源码映射。云厂商的每种资源、服务版本和证书替换语义仍需单独验收。[DNSMgr 部署配置](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/DeployHelper.php) · [Certimate 部署工厂](../internal/certmgmt/deployers/) · [部署驱动](../pkg/core/deployer/providers/)

| DNSMgr 部署驱动 | Certimate 对应路径（相对 `pkg/core/deployer/providers/`）及差异 |
| --- | --- |
| [宝塔面板（btpanel）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/btpanel.php) | [baotapanel](../pkg/core/deployer/providers/baotapanel/)、[baotapanel-console](../pkg/core/deployer/providers/baotapanel-console/) 原生模块覆盖站点、反代和面板；DNSMgr 的 Docker 站点、邮局模式仍需分别对照。 |
| [宝塔Win极速版（btwin）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/btwin.php) | [baotapanelgo](../pkg/core/deployer/providers/baotapanelgo/)、[baotapanelgo-console](../pkg/core/deployer/providers/baotapanelgo-console/) |
| [Kangle用户（kangle）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/kangle.php) | 用户虚拟主机证书、单域名证书。 [实现](../pkg/core/deployer/providers/dnsmgr-panels/kangle.go) · [用例](../pkg/core/deployer/providers/dnsmgr-panels/panels_test.go) |
| [Kangle管理员（kangleadmin）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/kangleadmin.php) | 管理员选择虚拟主机或更新面板证书。 [实现](../pkg/core/deployer/providers/dnsmgr-panels/kangle.go) · [用例](../pkg/core/deployer/providers/dnsmgr-panels/panels_test.go) |
| [雷池WAF（safeline）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/safeline.php) | [safeline](../pkg/core/deployer/providers/safeline/) |
| [堡塔云WAF（btwaf）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/btwaf.php) | [baotawaf](../pkg/core/deployer/providers/baotawaf/)、[baotawaf-console](../pkg/core/deployer/providers/baotawaf-console/) |
| [Cdnfly（cdnfly）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/cdnfly.php) | [cdnfly](../pkg/core/deployer/providers/cdnfly/) |
| [LeCDN（lecdn）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/lecdn.php) | [lecdn](../pkg/core/deployer/providers/lecdn/) |
| [GoEdge（goedge）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/goedge.php) | [goedge](../pkg/core/deployer/providers/goedge/)、[flexcdn](../pkg/core/deployer/providers/flexcdn/) |
| [南墙WAF（uusec）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/uusec.php) | 登录后按明确证书 ID 和名称更新。 [实现](../pkg/core/deployer/providers/dnsmgr-edge/panels.go) · [用例](../pkg/core/deployer/providers/dnsmgr-edge/deployer_test.go) |
| [SamWaf（samwaf）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/samwaf.php) | [samwaf](../pkg/core/deployer/providers/samwaf/)、[samwaf-console](../pkg/core/deployer/providers/samwaf-console/) |
| [1Panel（opanel）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/opanel.php) | [1panel](../pkg/core/deployer/providers/1panel/)、[1panel-console](../pkg/core/deployer/providers/1panel-console/) |
| [MW面板（mwpanel）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/mwpanel.php) | 逐站或控制台证书更新。 [实现](../pkg/core/deployer/providers/dnsmgr-hosts/mwpanel.go) · [用例](../pkg/core/deployer/providers/dnsmgr-hosts/mwpanel_test.go) |
| [AcePanel（acepanel）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/acepanel.php) | [ratpanel](../pkg/core/deployer/providers/ratpanel/)、[ratpanel-console](../pkg/core/deployer/providers/ratpanel-console/)。面板同名，3.x API 版本仍需核对。 |
| [耗子面板（ratpanel）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/ratpanel.php) | [ratpanel](../pkg/core/deployer/providers/ratpanel/)、[ratpanel-console](../pkg/core/deployer/providers/ratpanel-console/) |
| [小皮面板（xp）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/xp.php) | 列出站点并按唯一站点 ID 安装。 [实现](../pkg/core/deployer/providers/dnsmgr-edge/panels.go) · [用例](../pkg/core/deployer/providers/dnsmgr-edge/deployer_test.go) |
| AMH（amh） | **缺项**。AMH 的驱动文件保留在上游对照中。当前缺少已核实的受支持认证流程，部署工厂未注册 AMH。 |
| [CloudPanel（cloudpanel）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/cloudpanel.php) | 登录及签发材料导入使用会话和 CSRF；出现额外交互认证时停止。 [实现](../pkg/core/deployer/providers/dnsmgr-panels/cloudpanel.go) · [用例](../pkg/core/deployer/providers/dnsmgr-panels/panels_test.go) |
| [DirectAdmin（directadmin）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/directadmin.php) | 通过证书安装 API 逐域提交。 [实现](../pkg/core/deployer/providers/dnsmgr-panels/api_panels.go) · [用例](../pkg/core/deployer/providers/dnsmgr-panels/panels_test.go) |
| [群晖面板（synology）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/synology.php) | [synologydsm](../pkg/core/deployer/providers/synologydsm/) |
| [Lucky（lucky）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/lucky.php) | 按 SAN 或指定目标匹配，文件映射条目拒绝覆盖。 [实现](../pkg/core/deployer/providers/dnsmgr-edge/panels.go) · [用例](../pkg/core/deployer/providers/dnsmgr-edge/deployer_test.go) |
| [飞牛OS（fnos）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/fnos.php) | 飞牛 OS 使用带主机指纹校验的 SSH 调用管理员预装的无参数证书助手。助手在目标机校验证书和私钥、更新匹配证书、维护数据库及重启服务。真机版本与重载结果待验。[安装及权限](../pkg/core/deployer/providers/dnsmgr-extra/README.md) [实现](../pkg/core/deployer/providers/dnsmgr-extra/fnos.go) · [用例](../pkg/core/deployer/providers/dnsmgr-extra/fnos_test.go) |
| [Nginx Proxy Manager（nginxproxymanager）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/nginxproxymanager.php) | 按指定证书或代理主机绑定更新，包含重载与部分失败用例。 [实现](../pkg/core/deployer/providers/nginxproxymanager/nginxproxymanager.go) · [用例](../pkg/core/deployer/providers/nginxproxymanager/nginxproxymanager_test.go) |
| [Proxmox VE（proxmox）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/proxmox.php) | [proxmoxve](../pkg/core/deployer/providers/proxmoxve/) |
| [K8S（k8s）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/k8s.php) | 写入命名空间内的 TLS Secret，可更新所选 Ingress 的 TLS 绑定。 [实现](../pkg/core/deployer/providers/k8s-secret/ingress.go) · [用例](../pkg/core/deployer/providers/k8s-secret/ingress_test.go) |
| [阿里云（aliyun）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/aliyun.php) | [aliyun-cdn](../pkg/core/deployer/providers/aliyun-cdn/)、[aliyun-esa](../pkg/core/deployer/providers/aliyun-esa/)、[aliyun-clb](../pkg/core/deployer/providers/aliyun-clb/)、[aliyun-oss](../pkg/core/deployer/providers/aliyun-oss/)、[aliyun-waf](../pkg/core/deployer/providers/aliyun-waf/)、[aliyun-fc](../pkg/core/deployer/providers/aliyun-fc/) 上游含 19 个子产品/模式。原生还可定位 DCDN、ESA SaaS、ALB/NLB、API 网关、DDoS、直播、点播、GA、CAS 和 FC 2.0/3.0。[WAF 2.0](../pkg/core/deployer/providers/aliyun-waf/aliyun_waf2.go) 与 WAF 3.0 的云产品接入、CNAME 接入分别核对。 |
| [腾讯云（tencent）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/tencent.php) | [tencentcloud-cdn](../pkg/core/deployer/providers/tencentcloud-cdn/)、[tencentcloud-eo](../pkg/core/deployer/providers/tencentcloud-eo/)、[tencentcloud-clb](../pkg/core/deployer/providers/tencentcloud-clb/)、[tencentcloud-cos](../pkg/core/deployer/providers/tencentcloud-cos/)、[tencentcloud-scf](../pkg/core/deployer/providers/tencentcloud-scf/)、[TKE](../pkg/core/deployer/providers/tencentcloud-tke/)。 上游含 16 种产品/更新模式。TKE 以集群、命名空间和 Secret 标识目标。保留证书 ID 和新建 ID 替换、轻量应用服务器与云开发等模式须逐项验收。 |
| [华为云（huawei）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/huawei.php) | [huaweicloud-cdn](../pkg/core/deployer/providers/huaweicloud-cdn/)、[huaweicloud-elb](../pkg/core/deployer/providers/huaweicloud-elb/)、[huaweicloud-waf](../pkg/core/deployer/providers/huaweicloud-waf/) OBS 和仅上传证书分别可定位至 huaweicloud-obs、huaweicloud-scm。 |
| [UCloud（ucloud）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/ucloud.php) | [ucloud-ucdn](../pkg/core/deployer/providers/ucloud-ucdn/) |
| [七牛云（qiniu）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/qiniu.php) | [qiniu-cdn](../pkg/core/deployer/providers/qiniu-cdn/)、[qiniu-kodo](../pkg/core/deployer/providers/qiniu-kodo/) 视频直播另有 qiniu-pili。仅上传证书与各产品最终绑定需分别验证。 |
| [多吉云（doge）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/doge.php) | [dogecloud-cdn](../pkg/core/deployer/providers/dogecloud-cdn/) |
| [AxisNow（axisnow）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/axisnow.php) | [axisnow](../pkg/core/deployer/providers/axisnow/) |
| [又拍云（upyun）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/upyun.php) | [upyun-cdn](../pkg/core/deployer/providers/upyun-cdn/) |
| [百度云（baidu）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/baidu.php) | [baiducloud-cdn](../pkg/core/deployer/providers/baiducloud-cdn/)、[baiducloud-blb](../pkg/core/deployer/providers/baiducloud-blb/) 应用型 BLB 及证书上传另有 baiducloud-appblb、baiducloud-cert。 |
| [金山云（ksyun）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/ksyun.php) | [ksyun-cdn](../pkg/core/deployer/providers/ksyun-cdn/) |
| [火山引擎（huoshan）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/huoshan.php) | [volcengine-cdn](../pkg/core/deployer/providers/volcengine-cdn/)、[volcengine-clb](../pkg/core/deployer/providers/volcengine-clb/)、[volcengine-tos](../pkg/core/deployer/providers/volcengine-tos/)、[volcengine-live](../pkg/core/deployer/providers/volcengine-live/)、[volcengine-imagex](../pkg/core/deployer/providers/volcengine-imagex/) 其余模式映射至 volcengine-dcdn、volcengine-alb、volcengine-vod 和 volcengine-certcenter。 |
| [西部数码（west）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/west.php) | 西部数码虚拟主机按目标 FTP 站点安装。 [实现](../pkg/core/deployer/providers/dnsmgr-edge/west.go) · [用例](../pkg/core/deployer/providers/dnsmgr-edge/deployer_test.go) |
| [网宿科技（wangsu）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/wangsu.php) | [wangsu-cdn](../pkg/core/deployer/providers/wangsu-cdn/)、[wangsu-cdnpro](../pkg/core/deployer/providers/wangsu-cdnpro/)、[wangsu-certificate](../pkg/core/deployer/providers/wangsu-certificate/) 上游 CDN Pro 的证书管理与普通证书管理是两个模式，回执及资源绑定须分别验收。 |
| [白山云（baishan）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/baishan.php) | [baishan-cdn](../pkg/core/deployer/providers/baishan-cdn/) |
| [天翼云（ctyun）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/ctyun.php) | [ctcccloud-cdn](../pkg/core/deployer/providers/ctcccloud-cdn/)、[ctcccloud-ao](../pkg/core/deployer/providers/ctcccloud-ao/) 全站加速、函数计算分别可定位至 ctcccloud-icdn、ctcccloud-faas。 |
| [括彩云（kuocai）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/kuocai.php) | 使用登录会话和指定资源更新。 [实现](../pkg/core/deployer/providers/dnsmgr-extra/kuocai.go) · [用例](../pkg/core/deployer/providers/dnsmgr-extra/deployer_test.go) |
| [全栈云（qzyun）](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/deploy/qzyun.php) | 使用同源控制台的登录及证书操作，按名称或文档 ID 投递并可绑定 CDN 域名。控制台版本需实测。 [实现](../pkg/core/deployer/providers/dnsmgr-extra/qzyun.go) · [用例](../pkg/core/deployer/providers/dnsmgr-extra/qzyun_test.go) |
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

| 证据 | 可复核的范围 |
| --- | --- |
| Go 模块 | Go 1.26.6 下 `dnsauth`、`dnscatalog`、`dnsbatch`、`dnsautomation`、`dnsoptimize`、`dnsidentity`、`dnsmigrate` 七个包的定向测试通过。接口用例覆盖 v2 签名、nonce、订单导出授权及拒绝委托探测未批准的目标。[接口用例](../internal/dnsmcp/auth_test.go) |
| 浏览器 | DNS 账号页的 Chromium 用例验证 22 种可选授权；记录变更使用合成账号和模拟服务商请求。[账号用例](../tests/browser/dns-accounts.cjs) |
| 本地进程 | 轻量 PocketBase 进程挂载当前迁移、成员、目录、记录、批量接口以及回环 PowerDNS。四阶段测试通过，覆盖原授权与工作流图保留、跨账号拒绝、撤权、MX/TXT 变更和归档回读。发行程序可运行同一验收脚本。[进程验收](../tests/integration/acceptance.py) |
| 真实服务商 | 22 家 DNS 提供方的公网变更、8 个可选渠道的实际签发、51 个上游部署驱动所涉及的远端资源，以及通知送达，均需以各自授权账号和实际结果记录。本次离线核对没有使用真实凭据。 |


- 核对了上游固定提交的注册表、驱动文件、路由与目标方法。150 条路由中的 `/domain/dnscheck` 缺目标方法。`Index::doc` 有方法、无显式路由。`Index::test` 方法体为空。计数保留了这些差异。
- 基础 DNS 管理直接证据来自 [API 处理器](../internal/rest/handlers/dns.go)、[管理页面](../ui/src/pages/dns/DNSManager.tsx)、[Cloudflare HTTP 模拟用例](../pkg/sdk3rd/cloudflare/dns_test.go) 和[浏览器测试源码](../tests/browser/dns-records.cjs)。模拟响应与浏览器拦截能验证请求、表单或结果展示。真实账号的权限、配额、线路行为和公网最终生效需要单独记录。
- 签发与部署的映射依据为注册工厂与供应商实现。每个部署目标的真实验收至少要能确定证书投递到哪个资源、对外实际呈现的证书，以及服务商返回成功后的最终状态。
