# DNSMgr 固定版本的入口索引

本表给出上游声明的入口及其实现位置。对照时可按方法名回到控制器查看权限和写入行为，再到[能力对照表](dnsmgr-parity.zh-CN.md)核对 Certimate 的实现和验收状态。

## HTTP 路由和控制器

显式路由共 150 条，指向 142 个不同目标。已登录管理组 129 条，签名 API 组 10 条，其余 11 条各自处理登录、安装、回调、定时调度、任务状态或 MCP。表中路径已展开组前缀。

### Auth

| 入口 | 方法与路径 | 控制器方法 |
| --- | --- | --- |
| 独立 | [`ANY /login`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L25) | [login](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Auth.php#L12) |
| 独立 | [`GET /verifycode`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L27) | [verifycode](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Auth.php#L166) |
| 独立 | [`POST /auth/totp`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L28) | [totp](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Auth.php#L79) |
| 独立 | [`GET /logout`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L29) | [logout](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Auth.php#L110) |
| 独立 | [`ANY /quicklogin`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L30) | [quicklogin](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Auth.php#L116) |

### Cert

| 入口 | 方法与路径 | 控制器方法 |
| --- | --- | --- |
| 管理 | [`GET /cert/certaccount`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L140) | [certaccount](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L17) |
| 管理 | [`GET /cert/deployaccount`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L141) | [deployaccount](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L23) |
| 管理 | [`POST /cert/account/data`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L142) | [account_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L29) |
| 管理 | [`POST /cert/account/:action`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L143) | [account_op](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L73) |
| 管理 | [`GET /cert/account/:action`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L144) | [account_form](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L150) |
| 管理 | [`GET /cert/certorder`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L146) | [certorder](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L208) |
| 管理 | [`POST /cert/order/data`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L147) | [order_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L219) |
| 管理 | [`POST /cert/order/process`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L148) | [order_process](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L596) |
| 管理 | [`POST /cert/order/:action`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L149) | [order_op](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L293) |
| 管理 | [`GET /cert/order/:action`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L150) | [order_form](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L624) |
| 管理 | [`GET /cert/deploytask`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L152) | [deploytask](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L653) |
| 管理 | [`POST /cert/deploy/data`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L153) | [deploy_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L664) |
| 管理 | [`POST /cert/deploy/process`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L154) | [deploy_process](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L814) |
| 管理 | [`POST /cert/deploy/:action`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L155) | [deploy_op](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L725) |
| 管理 | [`GET /cert/deploy/:action`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L156) | [deploy_form](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L837) |
| 管理 | [`GET /cert/cname`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L158) | [cname](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L879) |
| 管理 | [`POST /cert/cname/data`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L159) | [cname_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L890) |
| 管理 | [`POST /cert/cname/:action`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L160) | [cname_op](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L932) |
| 管理 | [`GET /cert/certset`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L162) | [certset](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L1020) |
| 签名 | [`POST /api/cert/order`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L198) | [order_info](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L282) |

### Cloudflare

| 入口 | 方法与路径 | 控制器方法 |
| --- | --- | --- |
| 管理 | [`GET /cloudflare/hostnames/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L57) | [hostnames](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L14) |
| 管理 | [`POST /cloudflare/hostnames/data/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L58) | [hostnames_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L26) |
| 管理 | [`POST /cloudflare/hostnames/add/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L59) | [hostnames_add](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L40) |
| 管理 | [`POST /cloudflare/hostnames/update/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L60) | [hostnames_update](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L69) |
| 管理 | [`POST /cloudflare/hostnames/delete/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L61) | [hostnames_delete](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L135) |
| 管理 | [`POST /cloudflare/hostnames/refresh/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L62) | [hostnames_refresh](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L108) |
| 管理 | [`POST /cloudflare/hostnames/txttargets/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L63) | [hostnames_txt_targets](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L308) |
| 管理 | [`POST /cloudflare/hostnames/batch_add/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L64) | [hostnames_batch_add](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L243) |
| 管理 | [`POST /cloudflare/hostnames/batch_delete/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L65) | [hostnames_batch_delete](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L152) |
| 管理 | [`POST /cloudflare/hostnames/batch_update/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L66) | [hostnames_batch_update](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L185) |
| 管理 | [`POST /cloudflare/fallback/get/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L67) | [fallback_get](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L329) |
| 管理 | [`POST /cloudflare/fallback/set/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L68) | [fallback_set](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L340) |
| 管理 | [`POST /cloudflare/fallback/delete/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L69) | [fallback_delete](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L358) |
| 管理 | [`POST /cloudflare/dcv_delegation_uuid/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L70) | [dcv_delegation_uuid](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L370) |
| 管理 | [`POST /cloudflare/get_domain_default_line`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L71) | [get_domain_default_line](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L381) |
| 管理 | [`GET /cloudflare/tunnels/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L72) | [tunnels](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L463) |
| 管理 | [`POST /cloudflare/tunnels/data/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L73) | [tunnels_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L476) |
| 管理 | [`POST /cloudflare/tunnels/add/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L74) | [tunnels_add](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L490) |
| 管理 | [`POST /cloudflare/tunnels/delete/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L75) | [tunnels_delete](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L506) |
| 管理 | [`POST /cloudflare/tunnels/token/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L76) | [tunnels_token](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L522) |
| 管理 | [`POST /cloudflare/tunnels/publichostnames/data/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L77) | [tunnels_public_hostnames_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L537) |
| 管理 | [`POST /cloudflare/tunnels/publichostnames/save/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L78) | [tunnels_public_hostnames_save](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L559) |
| 管理 | [`POST /cloudflare/tunnels/publichostnames/delete/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L79) | [tunnels_public_hostnames_delete](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L623) |
| 管理 | [`POST /cloudflare/tunnels/cidr/data/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L80) | [tunnels_cidr_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L669) |
| 管理 | [`POST /cloudflare/tunnels/cidr/add/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L81) | [tunnels_cidr_add](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L690) |
| 管理 | [`POST /cloudflare/tunnels/cidr/delete/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L82) | [tunnels_cidr_delete](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L713) |
| 管理 | [`POST /cloudflare/tunnels/hostnameroutes/data/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L83) | [tunnels_hostname_routes_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L742) |
| 管理 | [`POST /cloudflare/tunnels/hostnameroutes/add/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L84) | [tunnels_hostname_routes_add](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L763) |
| 管理 | [`POST /cloudflare/tunnels/hostnameroutes/delete/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L85) | [tunnels_hostname_routes_delete](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cloudflare.php#L786) |

### Dmonitor

| 入口 | 方法与路径 | 控制器方法 |
| --- | --- | --- |
| 独立 | [`ANY /dmtask/status`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L31) | [status](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Dmonitor.php#L268) |
| 管理 | [`GET /dmonitor/overview`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L125) | [overview](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Dmonitor.php#L12) |
| 管理 | [`POST /dmonitor/task/data`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L126) | [task_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Dmonitor.php#L38) |
| 管理 | [`POST /dmonitor/task/log/data/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L127) | [tasklog_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Dmonitor.php#L238) |
| 管理 | [`GET /dmonitor/task/info/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L128) | [taskinfo](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Dmonitor.php#L215) |
| 管理 | [`POST /dmonitor/task/:action`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L129) | [task_op](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Dmonitor.php#L83) |
| 管理 | [`GET /dmonitor/task/:action`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L130) | [taskform](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Dmonitor.php#L191) |
| 管理 | [`GET /dmonitor/task`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L131) | [task](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Dmonitor.php#L32) |
| 管理 | [`POST /dmonitor/clean`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L132) | [clean](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Dmonitor.php#L256) |

### Domain

| 入口 | 方法与路径 | 控制器方法 |
| --- | --- | --- |
| 管理 | [`POST /account/data`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L52) | [account_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L23) |
| 管理 | [`POST /account/:action`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L53) | [account_op](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L78) |
| 管理 | [`GET /account/:action`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L54) | [account_add](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L60) |
| 管理 | [`GET /account`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L55) | [account](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L17) |
| 管理 | [`ANY /domain/expirenotice`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L87) | [expire_notice](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L1443) |
| 管理 | [`POST /domain/updatedate`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L88) | [update_date](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L1460) |
| 管理 | [`POST /domain/data`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L89) | [domain_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L202) |
| 管理 | [`POST /domain/op`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L90) | [domain_op](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L267) |
| 管理 | [`POST /domain/list`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L91) | [domain_list](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L388) |
| 管理 | [`ANY /domain/dnscheck`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L92) | `dnscheck`（无方法定义） |
| 管理 | [`POST /domain/category/data`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L93) | [category_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L1534) |
| 管理 | [`POST /domain/category/:action`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L94) | [category_op](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L1559) |
| 管理 | [`GET /domain/category/list`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L95) | [category_list](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L1605) |
| 管理 | [`POST /domain/setcategory`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L96) | [domain_set_category](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L1615) |
| 管理 | [`GET /domain/add`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L97) | [domain_add](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L181) |
| 管理 | [`GET /domain/category`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L98) | [category](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L1528) |
| 管理 | [`GET /domain`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L99) | [domain](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L155) |
| 管理 | [`POST /record/data/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L101) | [record_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L505) |
| 管理 | [`POST /record/add/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L102) | [record_add](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L588) |
| 管理 | [`POST /record/update/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L103) | [record_update](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L623) |
| 管理 | [`POST /record/delete/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L104) | [record_delete](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L675) |
| 管理 | [`POST /record/status/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L105) | [record_status](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L710) |
| 管理 | [`POST /record/remark/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L106) | [record_remark](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L747) |
| 管理 | [`POST /record/check/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L107) | [record_check](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L1472) |
| 管理 | [`POST /record/batch/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L108) | [record_batch](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L772) |
| 管理 | [`POST /record/batchedit/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L109) | [record_batch_edit](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L846) |
| 管理 | [`ANY /record/batchadd/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L110) | [record_batch_add](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L907) |
| 管理 | [`GET /record/batchadd`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L111) | [record_batch_add2](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L984) |
| 管理 | [`ANY /record/batchedit`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L112) | [record_batch_edit2](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L1022) |
| 管理 | [`ANY /record/log/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L113) | [record_log](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L1134) |
| 管理 | [`POST /record/groups/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L114) | [record_groups](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L1225) |
| 管理 | [`POST /record/list`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L115) | [record_list](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L561) |
| 管理 | [`POST /record/weight/data/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L116) | [weight_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L1340) |
| 管理 | [`ANY /record/weight/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L117) | [weight](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L1264) |
| 管理 | [`ANY /record/alias/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L118) | [alias](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L1364) |
| 管理 | [`GET /record/import/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L119) | [record_import](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L990) |
| 管理 | [`GET /record/search`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L120) | [record_search](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L1104) |
| 管理 | [`GET /record/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L121) | [record](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L470) |
| 管理 | [`GET /record/smartparse`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L122) | [smartparse](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L1158) |
| 管理 | [`POST /record/quickinfo/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L123) | [quickinfo](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L1187) |
| 签名 | [`POST /api/domain/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L187) | [domain_info](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L432) |
| 签名 | [`POST /api/domain`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L188) | [domain_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L202) |
| 签名 | [`POST /api/record/data/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L190) | [record_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L505) |
| 签名 | [`POST /api/record/add/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L191) | [record_add](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L588) |
| 签名 | [`POST /api/record/update/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L192) | [record_update](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L623) |
| 签名 | [`POST /api/record/delete/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L193) | [record_delete](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L675) |
| 签名 | [`POST /api/record/status/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L194) | [record_status](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L710) |
| 签名 | [`POST /api/record/remark/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L195) | [record_remark](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L747) |
| 签名 | [`POST /api/record/batch/:id`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L196) | [record_batch](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L772) |

### Index

| 入口 | 方法与路径 | 控制器方法 |
| --- | --- | --- |
| 管理 | [`ANY /`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L38) | [index](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Index.php#L13) |
| 管理 | [`POST /changeskin`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L39) | [changeskin](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Index.php#L111) |
| 管理 | [`GET /cleancache`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L40) | [cleancache](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Index.php#L126) |
| 管理 | [`ANY /setpwd`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L41) | [setpwd](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Index.php#L142) |
| 管理 | [`ANY /totp/:action`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L42) | [totp](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Index.php#L165) |
| 管理 | [`GET /test`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L43) | [test](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Index.php#L199) |
| 源码 | 无显式路由 | [doc](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Index.php#L135) |

### Install

| 入口 | 方法与路径 | 控制器方法 |
| --- | --- | --- |
| 独立 | [`ANY /install`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L22) | [index](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Install.php#L15) |

### Mcp

| 入口 | 方法与路径 | 控制器方法 |
| --- | --- | --- |
| 独立 | [`ANY /mcp`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L35) | [handle](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Mcp.php#L10) |

### Optimizeip

| 入口 | 方法与路径 | 控制器方法 |
| --- | --- | --- |
| 独立 | [`ANY /optimizeip/status`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L32) | [status](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Optimizeip.php#L191) |
| 管理 | [`ANY /optimizeip/opipset`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L134) | [opipset](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Optimizeip.php#L14) |
| 管理 | [`POST /optimizeip/queryapi`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L135) | [queryapi](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Optimizeip.php#L177) |
| 管理 | [`POST /optimizeip/opiplist/data`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L136) | [opiplist_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Optimizeip.php#L40) |
| 管理 | [`GET /optimizeip/opiplist`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L137) | [opiplist](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Optimizeip.php#L34) |
| 管理 | [`ANY /optimizeip/opipform/:action`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L138) | [opipform](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Optimizeip.php#L74) |

### Qqbot

| 入口 | 方法与路径 | 控制器方法 |
| --- | --- | --- |
| 独立 | [`ANY /qqbot/webhook`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L34) | [webhook](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Qqbot.php#L12) |

### Schedule

| 入口 | 方法与路径 | 控制器方法 |
| --- | --- | --- |
| 管理 | [`POST /schedule/stask/data`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L164) | [stask_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Schedule.php#L19) |
| 管理 | [`POST /schedule/stask/:action`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L165) | [stask_op](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Schedule.php#L63) |
| 管理 | [`GET /schedule/stask/:action`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L166) | [staskform](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Schedule.php#L150) |
| 管理 | [`GET /schedule/stask`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L167) | [stask](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Schedule.php#L13) |

### System

| 入口 | 方法与路径 | 控制器方法 |
| --- | --- | --- |
| 独立 | [`GET /cron`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L33) | [cron](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/System.php#L196) |
| 管理 | [`GET /system/loginset`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L169) | [loginset](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/System.php#L45) |
| 管理 | [`GET /system/noticeset`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L170) | [noticeset](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/System.php#L51) |
| 管理 | [`GET /system/proxyset`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L171) | [proxyset](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/System.php#L59) |
| 管理 | [`POST /system/set`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L172) | [set](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/System.php#L18) |
| 管理 | [`GET /system/mailtest`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L173) | [mailtest](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/System.php#L65) |
| 管理 | [`GET /system/tgbottest`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L174) | [tgbottest](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/System.php#L78) |
| 管理 | [`GET /system/webhooktest`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L175) | [webhooktest](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/System.php#L93) |
| 管理 | [`GET /system/customwebhooktest`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L176) | [customwebhooktest](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/System.php#L107) |
| 管理 | [`POST /system/proxytest`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L177) | [proxytest](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/System.php#L121) |
| 管理 | [`GET /system/cronset`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L178) | [cronset](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/System.php#L143) |
| 管理 | [`GET /system/update`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L179) | [update](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/System.php#L166) |
| 管理 | [`POST /system/checkupdate`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L180) | [checkupdate](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/System.php#L155) |
| 管理 | [`POST /system/doupdate`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L181) | [doupdate](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/System.php#L176) |

### User

| 入口 | 方法与路径 | 控制器方法 |
| --- | --- | --- |
| 管理 | [`POST /user/data`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L45) | [user_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/User.php#L25) |
| 管理 | [`POST /user/op`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L46) | [user_op](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/User.php#L50) |
| 管理 | [`GET /user`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L47) | [user](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/User.php#L13) |
| 管理 | [`POST /log/data`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L49) | [log_data](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/User.php#L170) |
| 管理 | [`GET /log`](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/route/app.php#L50) | [log](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/User.php#L165) |

### 同一控制器入口的动作参数

下表列出多动作表单和 API 的主要分派值。部分操作还有批量子动作，MCP 工具对外使用的名称列于下一节。

| 方法 | 分派值 |
| --- | --- |
| [Cert.account_op](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L73) | `add`、`edit`、`del` |
| [Cert.account_form](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L150) | `edit` |
| [Cert.order_op](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L293) | `get`、`add`、`edit`、`del`、`setauto`、`reset`、`revoke`、`show_log`、`operation`、`delete`、`open`、`close` |
| [Cert.order_form](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L624) | `edit` |
| [Cert.deploy_op](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L725) | `add`、`edit`、`del`、`setactive`、`reset`、`show_log`、`operation`、`cert`、`delete`、`open`、`close` |
| [Cert.deploy_form](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L837) | `edit` |
| [Cert.cname_op](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Cert.php#L932) | `add`、`edit`、`del`、`check` |
| [Dmonitor.task_op](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Dmonitor.php#L83) | `add`、`edit`、`setactive`、`del`、`operation`、`delete`、`retry`、`open`、`close` |
| [Dmonitor.taskform](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Dmonitor.php#L191) | `edit` |
| [Domain.account_add](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L60) | `edit` |
| [Domain.account_op](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L78) | `add`、`edit`、`del` |
| [Domain.domain_op](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L267) | `get`、`add`、`edit`、`del`、`batchadd`、`batchedit`、`batchsetnotice`、`batchdel`、`updateexpire` |
| [Domain.record_batch](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L772) | `open`、`pause`、`delete`、`remark`、`group` |
| [Domain.record_batch_edit](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L846) | `value`、`line` |
| [Domain.weight](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L1264) | `status`、`update` |
| [Domain.alias](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L1364) | `add`、`delete` |
| [Domain.category_op](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Domain.php#L1559) | `add`、`edit`、`del` |
| [Index.totp](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Index.php#L165) | `generate`、`bind`、`close` |
| [Optimizeip.opipform](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Optimizeip.php#L74) | `add`、`edit`、`setactive`、`del`、`run` |
| [Schedule.stask_op](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Schedule.php#L63) | `add`、`edit`、`setactive`、`del`、`operation`、`delete`、`open`、`close` |
| [Schedule.staskform](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/Schedule.php#L150) | `edit` |
| [User.user_op](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/controller/User.php#L50) | `get`、`add`、`edit`、`set`、`del` |

## MCP 工具和动作

上游从 5 个文件加载 28 个工具。每个动作在注册表内定义权限、参数及控制器调用。JSON-RPC 入口支持初始化、ping、工具枚举和调用。[MCP 服务](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/McpServer.php) · [工具分派](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/ToolRegistry.php)

| 工具文件 | 工具 | 动作 |
| --- | --- | --- |
| cert | [cert_account_query](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/cert.php#L10) | list |
| cert | [cert_account_manage](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/cert.php#L27) | add, edit, del |
| cert | [cert_order_query](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/cert.php#L67) | list, get, show_log |
| cert | [cert_order_manage](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/cert.php#L104) | add, edit, del, process, set_auto, reset, revoke, batch |
| cert | [cert_deploy_query](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/cert.php#L182) | list, show_log |
| cert | [cert_deploy_manage](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/cert.php#L209) | add, edit, del, set_active, reset, process, batch |
| cert | [cert_cname_query](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/cert.php#L266) | list |
| cert | [cert_cname_manage](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/cert.php#L282) | add, edit, del, check |
| cloudflare | [cf_hostname_query](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/cloudflare.php#L19) | list, txt_targets, fallback_get, dcv_uuid |
| cloudflare | [cf_hostname_manage](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/cloudflare.php#L52) | add, batch_add, update, batch_update, refresh, delete, batch_delete, fallback_set, fallback_delete |
| cloudflare | [cf_tunnel_query](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/cloudflare.php#L119) | list, token, public_hostnames, cidr_routes, hostname_routes |
| cloudflare | [cf_tunnel_manage](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/cloudflare.php#L157) | add, delete, public_hostname_save, public_hostname_delete, cidr_add, cidr_delete, hostname_route_add, hostname_route_delete |
| domain | [get_overview](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/domain.php#L15) | stat |
| domain | [list_provider_types](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/domain.php#L31) | query |
| domain | [dns_account_query](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/domain.php#L75) | list |
| domain | [dns_account_manage](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/domain.php#L91) | add, edit, del |
| domain | [domain_query](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/domain.php#L128) | list, get, info, quickinfo, aliases, remote_list, categories |
| domain | [domain_manage](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/domain.php#L198) | add, batch_add, edit, del, batch_del, batch_remark, batch_set_notice, refresh_expire, update_date, set_category, alias_add, alias_delete |
| domain | [domain_category_manage](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/domain.php#L291) | add, edit, del |
| domain | [operation_log_query](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/domain.php#L321) | list |
| record | [record_query](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/record.php#L28) | list, subdomain, log, groups, check, weight_list |
| record | [record_manage](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/record.php#L92) | add, update, delete, set_status, set_remark, batch, batch_edit, batch_add, edit_by_name, weight_status, weight_update |
| task | [dmonitor_query](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/task.php#L14) | overview, list, info, logs |
| task | [dmonitor_manage](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/task.php#L74) | add, edit, set_active, del, batch, clean_logs |
| task | [optimizeip_query](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/task.php#L138) | list, api_balance |
| task | [optimizeip_manage](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/task.php#L166) | add, edit, set_active, del, run |
| task | [schedule_query](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/task.php#L213) | list |
| task | [schedule_manage](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/lib/mcp/tools/task.php#L231) | add, edit, set_active, del, batch |

共 124 个工具动作。

## 数据与命令

安装脚本创建 17 张表。DNSMgr 的账号、域名、权限、别名、任务和订单均有本地 ID，导入时需保留它们的引用关系。[初始表结构](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/sql/install.sql) · [升级 SQL](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/sql/update.sql)

`config`、`account`、`domain`、`user`、`permission`、`log`、`dmtask`、`dmlog`、`optimizeip`、`cert_account`、`cert_order`、`cert_domain`、`cert_deploy`、`cert_cname`、`sctask`、`domain_alias`、`domain_category`。

| 已注册命令 | 职责 |
| --- | --- |
| [dmtask](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/command/Dmtask.php) | 轮询到期的启用任务，通过 Swoole 并发执行探测及切换。 |
| [certtask](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/command/Certtask.php) | 执行定时切换及优选任务。该轮没有执行优选时，再处理证书续期/部署和域名到期提醒。HTTP cron 有同一调用顺序。 |
| [reset](https://github.com/netcccyun/dnsmgr/blob/e0997e98ce348e9771256470bb3cb6820716a903/app/command/Reset.php) | 按用户名重置密码或关闭 TOTP。 |
