# Certimate DNS 进程级验收

在仓库根目录运行。需要 Python 3.9 或以上版本、与候选二进制匹配的 Go 工具链，以及已编译、可执行的 Certimate。

```sh
python3 tests/integration/acceptance.py --binary ./dist/certimate
```

测试先在空库启动候选程序并登录管理员。随后，它在另一个临时目录用 Certimate v0.4.38 的 16 次应用迁移与 PocketBase v0.39.10 初始化数据库。对应用迁移、快照和辅助源码的校验固定到提交 `e23f66928d82c9b1a623e31fcfcd631fca5d7aec`。测试经旧版集合 REST 接口创建 PowerDNS 授权及两份不同的工作流草稿和已发布图，再关闭旧进程，让候选程序升级原数据库。如果本地已有 v0.4.38 官方程序，可以通过 `--baseline-binary /path/to/certimate-v0.4.38` 直接使用该程序。

| 验收项 | 断言 |
| --- | --- |
| 管理台入口 | 空库管理员可查看 DNS 首页和部署任务，设置的站点主题可在登录前读取；普通成员访问管理汇总和部署列表会被拒绝。 |
| 升级与重复打开 | 保留已签发的管理员会话、管理员密码、原授权 ID 与配置、草稿和已发布图的内容、节点 ID、`providerAccessId`。再次打开后，账号停用状态和已有授权仍然生效。 |
| 目录 | 服务端公开的注册清单包含固定上游的 22 家驱动；两个模拟 PowerDNS 账号均含同名 Zone。管理员同步后能看到三个独立条目，域名详情能关联升级前的工作流。返回的数据不会包含合成凭据。 |
| 集合规则 | 经管理员查询集合定义，逐项检查 DNS 集合、`access` 与 `workflow` 的五类 REST 规则。普通成员读取集合、匿名读取凭据、成员直接创建 Zone 授权均被拒绝。 |
| 成员权限 | 无授权、工作区只读、同域编辑授权叠加、撤销编辑授权。列表总数和分页匹配实际可见域。跨域、同名跨账号及匿名请求在读取、写入、删除和导出之前被拒绝。 |
| 批量变更 | 编辑者预览同一批 MX 和 TXT，再确认执行。按行验证结果，回读导出的域名、TTL、MX 优先级与目标。重复提交受到拦截，撤销编辑权限后，已保存的删除计划也无法执行。 |
| 记录和停用 | 已登录的编辑者通过真实 HTTP 路由完成 TXT 新增、查询、修改、删除，以及用一次 PowerDNS Zone PATCH 将 TXT 改名并转换为指定优先级的 MX。验证目标记录 ID 变化、已有源和目标记录保留，过期快照在写入前被拒绝。禁用账号会阻止成员和管理员访问提供方，并阻止同步；重新启用后原工作区授权恢复。禁用成员使其现有会话失去读取能力。 |

每次运行都会生成临时密码、PowerDNS 测试密钥和本地数据库。应用和提供方均绑定回环地址。真实 DNS 发布、ACME 签发与清理、商业订单、远端证书部署及消息送达需要在获授权的环境单独验收。

## DDNS 设备上报与同步

需要编译好的 Linux Rust DDNS 客户端和 `openssl`。测试由临时 CA 签发回环 HTTPS 服务证书，验证客户端拒绝不受信任的 CA，并在指定 CA 后通过 HTTPS 上报。之后用固定的网卡、MAC、IPv4 和 IPv6 数据验证服务端行为。

```sh
(cd cmd/ddns-agent-native && cargo build --locked --release)
python3 tests/integration/ddns_acceptance.py --binary ./dist/certimate \
  --agent cmd/ddns-agent-native/target/release/certimate-ddns-agent
```

验收覆盖管理员和设备授权、设备上线和信息展示、令牌轮换及撤销。PowerDNS 模拟器回读两轮地址变更，验证绑定的 A 和 AAAA 记录保留各自的 TTL，其他记录保持原值。
