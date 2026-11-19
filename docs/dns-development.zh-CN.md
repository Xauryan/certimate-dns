# Certimate DNS 开发基线

本分支基于 Certimate v0.4.38。管理台复用原有授权凭据和证书工作流，并增加 DNS 域名目录、成员授权、解析自动化、商业证书和接口密钥。下文保留项目最初的路线图和验收条件。逐项实现、协议差异及待验能力见[彩虹 DNS 功能对照](dnsmgr-parity.zh-CN.md)。

## 复现基线

使用 Git、Node.js 24、npm 11.10 或以上版本，以及 go.mod 指定的 Go 工具链。在全新目录运行以下命令。首次启动会创建开发专用的 PocketBase 数据库。

```sh
git clone --recurse-submodules https://github.com/Xauryan/certimate-dns.git
cd certimate-dns
npm --prefix ui ci
npm --prefix ui run build
mkdir -p dist
CGO_ENABLED=0 go build -mod=readonly -trimpath -o dist/certimate .
./dist/certimate serve --dir ./pb_data --http 127.0.0.1:8090
```

浏览器打开 http://127.0.0.1:8090/ 。健康检查在 /api/health。CI 在 GitHub 托管的标准 ubuntu-26.04 x64 机器上构建相同的前端和 Go 可执行文件。进程测试打开临时空库，并从 v0.4.38 的数据库升级后检查会话、工作流、跨域权限、批量变更及重启恢复。CI 的权限为读取仓库内容，测试使用本地数据。

## 安装、升级与回退

**首次安装。** 从 [Certimate DNS Releases](https://github.com/Xauryan/certimate-dns/releases) 选择对应系统和架构的发行包，核对发行附带的校验值。发行页没有可用构建时，按上文从 Certimate DNS 源码构建。用稳定的数据目录启动，例如 `./certimate serve --dir ./pb_data --http 127.0.0.1:8090`。首次启动前通过服务环境设置 `CERTIMATE_ADMIN_USERNAME` 和 `CERTIMATE_ADMIN_PASSWORD`，空库迁移会用它们初始化管理员。服务启动后访问 `/api/health`，再登录管理台。容器安装从仓库根目录执行 `docker compose -f docker/docker-compose.yml up -d --build`，样例从当前源码构建，数据保存在 `docker/data/`。

**升级现有 Certimate 或 Certimate DNS。** 目前进程测试覆盖的是从 Certimate v0.4.38 原库升级。取得目标 Certimate DNS 版本的二进制或构建容器镜像。停止旧实例，保留旧程序或镜像并完整备份现有 `--dir` 目录，包括隐藏文件和存储目录。使用 PocketBase `--encryptionEnv` 时，保留原环境里的加密密钥。启动新版本时沿用原数据目录、加密配置和监听配置，PocketBase 在启动时执行迁移。检查 `/api/health` 和启动日志，并确认原账号、授权、证书工作流和已有 DNS 配置可以打开。容器升级沿用原数据卷或绑定目录。

**回退。** 停止升级后的实例，用升级前的完整备份恢复数据目录，再启动相应的旧程序或镜像。迁移彩虹 DNS 的 MySQL 数据时，按[迁移指南](dnsmgr-migration.zh-CN.md)另行导入。

管理台只检查 Certimate DNS 仓库发布的稳定版，提示指向对应的发行包页面。准备发布时，将 `internal/app/app.go` 中的 `AppVersion` 与 `vX.Y.Z` 发行标签对应，保证构建内嵌版本与发行版一致。站点后台任务随主进程运行，设置中的「诊断」提供日志及 Certimate 工作流调度统计。

## 使用 Cloudflare DNS 管理

管理员进入「DNS 解析管理」，选择已有的 Cloudflare 授权，再点击域名。Zone 与记录按服务商分页，记录名搜索在服务端执行。读取 Zone 需要 Zone Read，读取和导出记录需要 DNS Read，写入需要相应 Zone 的 DNS Edit 权限。配置了独立 Zone token 时，域名枚举使用该 token，记录操作使用主 token。

- 新增支持 A、AAAA、CNAME 和 TXT。填写完整记录名，TTL 为 1 时使用自动值。编辑提交记录值和 TTL，保留 Cloudflare 的代理状态、标签及备注。
- 删除确认框显示类型、名称和记录值。服务商调用的操作结果进入应用日志，日志使用资源 ID 标识操作。请求中断时先刷新列表核对结果。
- 「导出 BIND 区域文件」从 Cloudflare 获取整个 Zone，与当前列表页和名称筛选独立。
- DNS-01 工作流继续通过相同的 Cloudflare 授权记录取凭据。当前功能复用原有数据库，无需迁移账号。

## 源码映射

Certimate 基线提交为 [e23f669](https://github.com/certimate-go/certimate/tree/e23f66928d82c9b1a623e31fcfcd631fca5d7aec)，SDK 子模块随该提交固定为 baf25c1。DNSMgr 的业务参考版本为 [e0997e9](https://github.com/netcccyun/dnsmgr/tree/e0997e98ce348e9771256470bb3cb6820716a903)。

| 要做的能力 | DNSMgr 业务参考 | Certimate 中的接入点 |
| --- | --- | --- |
| 账号、Zone、记录 | app/lib/DnsInterface.php 定义分页查询、线路、最小 TTL、增删改，app/controller/Domain.php 处理域名操作 | internal/repository/access.go 已能读取授权配置。新增 internal/dns，给每家服务商实现管理接口和能力清单 |
| 服务商差异 | app/lib/dns/aliyun.php、dnspod.php、cloudflare.php | pkg/core/certifier/challengers/dns01 下的 aliyun、tencentcloud、cloudflare 已处理 ACME 挑战。管理适配器与挑战适配器共享授权记录 ID |
| 数据与访问权限 | app/sql/install.sql、app/controller/Auth.php | migrations/ 扩展 PocketBase，internal/rest/routes/routes.go 的 API 路由组使用 RequireSuperuserAuth。首期在这个路由组内注册 DNS 接口 |
| 证书工作流 | 域名与验证账号的关联 | internal/domain/workflow.go 的 providerAccessId 和 internal/workflow/engine/executor_bizapply.go。保留已有图和节点标识，新增账号选择与解析逻辑 |
| 管理界面 | 域名列表、记录编辑、线路及 TTL 选项 | ui/src/pages/ConsoleLayout.tsx、ui/src/routers/、ui/src/pages/accesses/。扩展现有导航和授权选择控件 |
| 容灾、定时变更与优选 IP | app/controller/Dmonitor.php、app/service/ScheduleService.php、app/service/OptimizeService.php | internal/scheduler/ 与 main.go 的服务生命周期。后续在统一调度器中注册任务 |

## 首个里程碑 · 三家服务商的 DNS 管理

1. **授权和数据模型。** 在 PocketBase 增加 DNS 账号与 Zone，账号引用已有 access 记录。Zone 以账号和服务商 Zone ID 唯一定位。记录列表以服务商返回值为准。验收覆盖空库升级、已有库升级、禁用账号以及旧证书工作流读取。
2. **读写接口。** 为阿里云 DNS、腾讯云 DNSPod、Cloudflare 实现 Zone 分页和记录查询、新增、修改、删除。接口返回各家的 TTL、线路、代理状态等能力。测试覆盖根记录、泛域名、分页、限流和拒绝访问。写入超时后按服务商记录 ID 回读，避免重复创建。
3. **界面和权限。** 在管理台增加账号、Zone 和记录页面。服务端校验账号与 Zone 的关联，写操作记录操作者、资源 ID 和结果。匿名访问、跨账号拼接资源 ID、敏感配置出现在列表或日志都列入回归测试。
4. **复用 DNS-01 授权。** 新工作流可选择 DNS 管理账号，已有 providerAccessId 继续有效。对同一账号、Zone 和规范化记录名的并发 TXT 更新做协调。测试同时申请根域和通配符，清理其中一项后，另一项和预先存在的 TXT 值都应保留。
5. **验收。** 三个适配器分别通过使用模拟服务的相同契约用例。另在获授权的测试 Zone 完成一次真实记录 CRUD、一次签发和一次清理，记录各家结果。云凭据通过部署环境提供。

## 后续开发

| 阶段 | 交付与验收条件 |
| --- | --- |
| DNS 自动化 | 增加批量变更、定时解析、容灾切换和通知。连续失败触发切换，恢复阈值和冷却期控制回切。任务租约、人工暂停、变更前快照和执行后回读覆盖重启与重复触发。Cloudflare 优选 IP 单独验收。 |
| 统一资源与迁移 | 域名详情页关联记录、证书和自动化。扩展工作区授权、监控及 API/MCP。DNSMgr 数据先导出为带版本的中间格式，预览旧账号和 Zone 的 ID 映射，逐项验证后才启用导入的任务。 |
