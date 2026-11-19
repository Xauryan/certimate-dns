# Certimate DNS 开发基线

本分支从 Certimate v0.4.38 建立。当前可运行的功能来自上游 Certimate。DNS 管理是本分支的开发目标，下面的验收项用于判断何时可以发布首个 DNS 功能版本。

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

浏览器打开 http://127.0.0.1:8090/ 。健康检查在 /api/health。CI 在 GitHub 托管的标准 ubuntu-26.04 x64 机器上构建相同的前端和 Go 可执行文件，再用临时空库检查首页和健康接口。CI 的权限为读取仓库内容，测试使用本地数据。

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
