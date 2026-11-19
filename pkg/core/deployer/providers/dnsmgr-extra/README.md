# 飞牛 OS 证书部署

飞牛主机需开启过 HTTPS。部署使用 SSH 密码登录，并核对工作流凭据中填写的 SHA256 主机密钥指纹。请从飞牛主机控制台读取所用主机密钥的指纹，例如执行 `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256`。

管理员在飞牛主机上，从已核对的本版本源码安装助手。主机需提供带 OpenSSL 的 CPython 3.8 或更新版本、Linux procfs、PostgreSQL 客户端和 systemd。助手和所在目录须由 root 持有，且仅 root 可写。

```sh
sudo install -o root -g root -m 0755 pkg/core/deployer/providers/dnsmgr-extra/fnos_update.py /usr/local/sbin/certimate-fnos-update
sudo visudo -f /etc/sudoers.d/certimate-fnos-update
```

以下规则中的 `certimate` 为部署专用 SSH 用户名。末尾的 `""` 将授权限制为无参数调用，`NOSETENV` 限制调用方设置环境变量。

```sudoers
certimate ALL=(root) NOPASSWD: NOSETENV: /usr/local/sbin/certimate-fnos-update ""
```

保存后执行 `sudo visudo -c` 检查配置。助手从标准输入接收证书链和私钥，在主机上检查密钥匹配及有效期，并从叶证书读取 SAN、签发者和有效期。它根据 `/usr/trim/etc/network_cert_all.conf` 中已登记的 SAN 更新证书，要求新证书覆盖匹配条目的所有域名。目录、清单、证书和私钥均需由 root 持有，且组及其他用户无写权限。

助手串行更新证书文件与数据库，随后重启 `webdav.service`、`smbftpd.service` 和 `trim_nginx.service`。另一项部署正在更新时，本次调用会返回忙碌状态。若 SSH 在提交后中断，远端助手会继续完成更新。请核对证书、数据库及服务状态后再重试。
