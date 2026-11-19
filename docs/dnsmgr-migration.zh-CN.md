# 从 DNSMgr 迁入本地目录

`dnsmgr-migrate` 读取 DNSMgr schema 1049 的 MySQL/InnoDB 快照，生成版本化 JSON。目标端需要已运行本项目迁移的 Certimate 数据目录。导入只写本地数据库。每个源安装使用固定且唯一的 `-source`，时区使用源 PHP 配置。

## 导出并预演

1. 在 Certimate 的授权管理中新建或确认与旧账号对应的服务商授权。记录其 access ID。
2. 通过终端的安全输入或既有密钥管理工具设置环境变量 `DNSMGR_MYSQL_DSN`。使用仅有源库 SELECT 权限的账号。导出文件路径必须尚不存在。
3. 在仓库根目录执行下列命令。将数据目录和示例账号 ID 替换为自己的值。

```sh
go build -o /tmp/dnsmgr-migrate ./cmd/dnsmgr-migrate
/tmp/dnsmgr-migrate export -source legacy-a -prefix dnsmgr_ -timezone Asia/Shanghai -out inventory.json
```

在 `bindings.json` 中把旧账号数字 ID 对应到 Certimate 的授权记录 ID。绑定文件只填写标识符。

```json
{"version":1,"source":"legacy-a","accounts":{"7":"exampleaccess01"}}
```

```sh
/tmp/dnsmgr-migrate dry-run -dir ./pb_data -in inventory.json -bindings bindings.json
/tmp/dnsmgr-migrate import -dir ./pb_data -in inventory.json -bindings bindings.json
```

预演以只读方式打开现有 `data.db`，输出每项的源类型、旧 ID、目标 ID、处理方式和冲突原因。报告中有 `conflict` 时命令返回非零，整批导入停止。导入在写事务内重新核对映射。首次执行会记录来源、旧 ID、目标 ID 与内容摘要。用相同输入重试返回 `unchanged`，保留目标端后续编辑。源内容、绑定或已导入的目标发生身份冲突时，报告指出需要核对的条目。导入失败时，整个事务回滚。

## 迁移范围

| 来源 | 结果 |
| --- | --- |
| DNS 账号和域名 | 支持内置注册表的 22 种 DNSMgr 服务商。绑定检查目标授权的类型和删除状态。通过账号及服务商 Zone ID 匹配现有域名，新建域名保存旧名称、注册日、到期日、隐藏状态及分类，初始状态为待同步。相同目标复用既有元数据。 |
| 分类和别名 | 分类按名称复用或按源 ID 映射新建，保存排序。别名保留与原域名的关系，供管理员核对服务商端配置。 |
| 定时任务和故障切换 | 可验证记录身份的定时改值、部分 TCP 探测创建为草稿。一次性时间按源时区解析。需重新选择记录、调整参数或核对代理设置的任务进入复核清单。源任务的启用标记保存在中间文件中。 |
| 优选 IP | 保存原域名、主机记录、模式、地址族、CDN 类别、数量和 TTL 供复核。重新选择候选源和解析线路后创建目标任务。 |
| 用户、权限、证书账号、订单、证书域名、部署和 CNAME 委派 | 逐项保存源 ID、关联 ID 和所选状态或域名字段，标记为 `stage`。在目标系统重新确认身份、授权、挑战及部署依赖。源密码、API 密钥、TOTP 种子、账户配置、证书私钥、证书正文和部署配置均排除在导出之外。 |
| 配置、操作日志和监控日志 | 保存 schema 版本和三张表的行数。日志正文、邮件配置和探测 URL 留在源库。 |

清单最大 64 MiB，导出文件权限为 0600。该格式用于迁移所列资源，完整数据库灾备仍使用源系统备份。导入后先同步域名，核对服务商实际记录及任务的目标、动作、时区、阈值和通知，再由管理员启用。导入过程不签发证书、不修改远端 DNS、不启用快捷登录或到期通知。

## 验证

`GOTOOLCHAIN=go1.26.6 go test ./cmd/dnsmgr-migrate ./internal/dnsmigrate` 使用临时库覆盖字段过滤、孤立引用、文件权限、预演、导入中途回滚、重复导入和源数据冲突。另用原版 schema 1049 和本地 MariaDB 11.8.6 的 SELECT 用户验证了实际导出。
