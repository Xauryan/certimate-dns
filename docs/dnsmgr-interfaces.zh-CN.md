# DNSMgr 签名 API 与 MCP

在管理界面的「接口密钥」或 DNS 成员门户创建密钥，选择接口、动作和本地域名。管理员可以显式选择授权账户或全局管理操作。成员需要管理员开启 API 权限。创建时显示 UID 和密钥，列表仅返回标签与范围。撤销密钥、停用成员或撤销域名授权会影响后续调用。域名、账户和全局范围分别检查，选择全局管理权限不会自动授权所有账户或域名。

## 签名 HTTP API

向下列路径提交 URL 编码的 POST 表单。时间戳使用 Unix 秒，允许与服务器相差 300 秒。证书与域名应使用此 Certimate 实例提供的 ID。

| 路径 | 动作 | 签名 |
| --- | --- | --- |
| `/api/domain` | 列出已授权域名，支持筛选、排序、分页，返回稳定的数字域名 ID | v1 或 v2 |
| `/api/domain/{id}` | 域名详情、解析线路、最低 TTL | v1 或 v2 |
| `/api/record/data/{id}` | 解析记录列表 | v1 或 v2 |
| `/api/record/{add,update,delete,status,remark,batch}/{id}` | 解析记录操作 | v2 |
| `/api/cert/order` | 导出授权订单的证书、私钥，可选 PFX | v2 |

请求域名详情时增加 `loginurl=1` 也需要 v2、`domain.login`、`domain.read`、`record.read` 和域名开启快捷登录。返回的链接只能领取一次，产生的只读会话绑定原密钥和域名。

DNSMgr 原版签名 v1 使用小写十六进制 `MD5(uid + timestamp + apikey)`。同一个签名可以在其五分钟窗口内随其他路径、请求体重复提交，因此上述敏感操作需要 v2。原版 PHP 客户端需升级签名才能写入此服务。

v2 表单包含 `uid`、`timestamp`、`sign_version=2`、`nonce` 以及全部业务字段。使用密码学随机源生成 16 字节 nonce，以 32 个小写十六进制字符传递。下列 Go 代码表示签名计算，其中 `form` 是 `url.Values`、`escapedPath` 是接口的完整转义路径，例如 `/api/record/add/1`。

```go
form.Del("sign")
message := "DNSMgr-v2\nPOST\n" + escapedPath + "\n" + form.Encode()
mac := hmac.New(sha256.New, []byte(apikey))
mac.Write([]byte(message))
form.Set("sign", hex.EncodeToString(mac.Sum(nil)))
```

`Encode()` 按字段名升序排列，空格编码为 `+`，再用 `&` 连接各个键值。每个字段只允许出现一次，路径不含查询串。发起请求前再生成时间戳和 nonce。服务端在分派前持久登记 nonce，同一密钥与 nonce 的请求只受理一次。连接中断时先核对服务商状态，再决定是否发起新的写操作。

## MCP

向 `/mcp` 发送 JSON-RPC 2.0 POST 请求，以 `Authorization: Bearer UID:APIKEY` 认证。支持 `initialize`、`ping`、`tools/list` 和 `tools/call`。批请求最多含 32 条消息。调用批量变更需要工具动作权限及对应的实际修改权限。客户端可以先调用 `domain_query(list)` 获取本地字符串 ID。签名 HTTP 客户端从 `/api/domain` 获取数字域名 ID。

固定版本定义 28 个工具、124 个动作。服务只枚举当前角色和密钥获准的动作。覆盖证书、Cloudflare、域名、记录和任务五组，完整名称见[入口索引](dnsmgr-entrypoints.zh-CN.md)。执行结果随服务商能力和本地配置而变化。例如记录改名或类型转换需要底层服务商的支持，当前通用更新路径仅修改值、TTL 和可用属性。Cloudflare Tunnel 令牌以调用方接收公钥加密返回。商业 CA 订单使用本地版本控制和额度确认。新任务先保存为草稿，优选 IP 在启用或执行前需要确认预览摘要。导入的源端 ID、草稿和凭据的具体处理见[迁移说明](dnsmgr-migration.zh-CN.md)。
