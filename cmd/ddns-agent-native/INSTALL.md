# Certimate DDNS 客户端安装

在 GitHub Release 页面下载文件名以 `certimate-ddns-agent_` 开头、与本机系统匹配的 x64 ZIP，以及同一版本的 `checksums.txt`。Linux 用 `sha256sum 文件名.zip`，Windows PowerShell 用 `Get-FileHash 文件名.zip -Algorithm SHA256`，与校验清单中对应文件名的值比对后解压。以下命令从解压目录执行。

## 登记节点

用管理员账号打开 Certimate 的「DNS → DDNS 管理 → 注册节点」。将一次性显示的令牌写入本机的 `agent.json`，并填入可通过系统信任证书访问的 Certimate HTTPS 地址。

```json
{
  "server": "https://certimate.example.org",
  "token": "REPLACE_WITH_NODE_TOKEN"
}
```

默认上报已启用的非回环网卡。需要限定网卡时，可添加 `"interfaces": ["ens18"]`，Windows 填写 `Get-NetAdapter` 显示的网卡名称。已有节点升级时沿用其私有配置文件和原节点令牌。

## Linux x64

需要系统 CA 证书、glibc、libgcc 和支持服务凭据的 systemd。以下步骤使用发行包附带的两个 systemd 单元。

```sh
sudo install -d -m 0700 /etc/certimate-ddns
sudoedit /etc/certimate-ddns/agent.json
sudo chmod 0600 /etc/certimate-ddns/agent.json
sudo install -m 0755 certimate-ddns-agent /usr/local/bin/certimate-ddns-agent-native
sudo install -m 0644 certimate-ddns-agent-native.service certimate-ddns-agent-native.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start certimate-ddns-agent-native.service
sudo systemctl enable --now certimate-ddns-agent-native.timer
systemctl list-timers certimate-ddns-agent-native.timer
```

首次安装时在编辑器中填入上面的 JSON。已有配置时可跳过编辑。用 `systemctl show certimate-ddns-agent-native.service -p Result -p ExecMainStatus` 核对最近一次执行成功。

## Windows x64

在管理员 PowerShell 中创建仅 SYSTEM 和管理员可访问的目录，再写入配置。使用系统证书存储校验服务端身份。

```powershell
$ErrorActionPreference = 'Stop'
$dir = 'C:\ProgramData\CertimateDDNS'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
icacls.exe $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)'
if ($LASTEXITCODE -ne 0) { throw 'Unable to protect the DDNS directory' }
Copy-Item .\certimate-ddns-agent.exe "$dir\certimate-ddns-agent-native.exe"
notepad.exe "$dir\agent.json"
```

保存配置后运行以下命令，已有配置时可直接使用。首次上报成功后创建每五分钟执行一次的 SYSTEM 计划任务。

```powershell
& "$dir\certimate-ddns-agent-native.exe" --config "$dir\agent.json"
if ($LASTEXITCODE -ne 0) { throw 'DDNS report failed' }
$action = "$dir\certimate-ddns-agent-native.exe --config $dir\agent.json"
schtasks.exe /Create /TN CertimateDDNS /SC MINUTE /MO 5 /RU SYSTEM /TR $action /F
if ($LASTEXITCODE -ne 0) { throw 'Unable to register the DDNS task' }
```

## 核验和绑定

回到「DDNS 管理」核对该节点的最近上报时间、MAC 和双栈地址。迁移已有动态解析时，先停止原写入方，再选择上报的网卡并绑定对应的现有 A 或 AAAA 记录。同步成功后核对权威 DNS。节点客户端只使用自己的上报令牌，DNS 凭据在 Certimate 管理。

要给已绑定的记录改名，在「DNS 绑定」找到对应的 A 或 AAAA 行，点击「编辑绑定」，填写同一区内的新名称并保存。保存后，Certimate 会核对服务商上的改名结果，后续上报会更新新名称。A 和 AAAA 是两条独立记录；双栈域名两条都要改名时，分别编辑对应行。递归 DNS 中的旧答案可能保留至原 TTL 到期。

如果服务商已收到改名请求但暂时无法核验，绑定行会显示待核验的新名称。恢复连接后可在该行重新核验。若服务商更换了记录 ID 且没有返回新 ID，核对候选记录后再确认绑定。
