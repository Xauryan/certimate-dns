# Certimate DDNS 节点客户端

一次执行读取主机名、网卡、MAC、IPv4 和 IPv6，通过 HTTPS 上报给 Certimate。Linux 的 systemd timer 或 Windows 的计划任务按五分钟周期启动客户端。域名绑定和 DNS 服务商凭据保存在 Certimate，服务端根据绑定更新解析。

从 [GitHub Releases](https://github.com/Xauryan/certimate-dns/releases) 下载对应系统的 `certimate-ddns-agent_` 压缩包并核对同版 `checksums.txt`。解压后的安装步骤见包内的 `README.md`。 [发行包安装说明](INSTALL.md)

## 构建

需要 Rust 1.85 或更新版本和 Cargo。`Cargo.lock` 固定依赖版本。Release 配置使用 `opt-level = "z"`、LTO 和一个代码生成单元，设置 `panic = "abort"` 并剥离符号。在 `cmd/ddns-agent-native` 目录构建并测试 Linux 版本。

```sh
cargo test --locked
cargo build --locked --release
```

Linux x64 产物为 `target/release/certimate-ddns-agent`。HTTPS 使用随程序构建的 Rustls 和 ring，并从系统 CA 信任库读取证书。运行环境需要兼容构建目标的 glibc、libgcc 和 CA 证书，例如 Ubuntu 24.04 的 `ca-certificates`。从源码构建 Linux 版还需要 C 工具链，以编译 ring。

在 Windows 上使用带 MSVC 链接工具的 Rust 工具链运行同样的 Cargo 命令，生成 `target/release/certimate-ddns-agent.exe`。Windows 程序使用系统的 WinHTTP、IP Helper 和证书存储。在 Linux 上安装 MinGW x64 编译器后，也可使用与 CI 相同的方式交叉构建 Windows x64 版本。

```sh
rustup target add x86_64-pc-windows-gnu
cargo build --locked --release --target x86_64-pc-windows-gnu
```

交叉构建的产物在 `target/x86_64-pc-windows-gnu/release/`。目标主机安装可执行文件和配置即可。

## 节点配置

在 Certimate 的「DNS → DDNS」创建节点。将界面仅显示一次的节点令牌写入该节点的私有文件 `agent.json`。

```json
{
  "server": "https://certimate.example.org",
  "token": "REPLACE_WITH_NODE_TOKEN",
  "interfaces": ["ens18"]
}
```

`server` 填 HTTPS 站点地址。可选的 `hostname` 缺省时使用系统主机名。可选的 `interfaces` 接受网卡名数组，省略时上报已启用的非回环网卡。Linux 可用 `ip link` 查看网卡名，Windows 可用 `Get-NetAdapter`。收到 HTTP `204` 时程序返回 `0`，采集或上报失败时返回非零退出码。

## Linux systemd

系统服务需要 systemd 247 或更新版本。以下命令在仓库根目录执行，由 systemd 将 root 持有的 `agent.json` 以只读凭据交给每次启动的临时服务身份。

```sh
sudo install -d -o root -g root -m 0700 /etc/certimate-ddns
sudo install -o root -g root -m 0600 agent.json /etc/certimate-ddns/agent.json
sudo install -o root -g root -m 0755 cmd/ddns-agent-native/target/release/certimate-ddns-agent \
  /usr/local/bin/certimate-ddns-agent-native
sudo install -o root -g root -m 0644 \
  deploy/systemd/certimate-ddns-agent-native.service deploy/systemd/certimate-ddns-agent-native.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start certimate-ddns-agent-native.service
sudo systemctl enable --now certimate-ddns-agent-native.timer
```

计时器启用后会安排首次上报，此后每五分钟触发一次。固定的机器偏移将上报分散到每个周期起点之后约 45 秒的窗口内。连接失败时可从服务日志查看结果，下一次定时触发时会重新上报。轮换令牌后更新配置，下一次执行会读取新文件。也可用 `systemctl start certimate-ddns-agent-native.service` 立即验证。

```sh
systemctl list-timers certimate-ddns-agent-native.timer
systemctl show certimate-ddns-agent-native.service -p Result -p ExecMainStatus -p MainPID
journalctl -u certimate-ddns-agent-native.service -n 20 --no-pager
```

从旧 Go 常驻客户端切换时，先用新版本完成一次上报，再停用 `certimate-ddns-agent.service` 并启用新 timer。面板上的原节点和记录绑定可继续使用。

## Windows 计划任务

从管理员 PowerShell 执行，当前目录包含 `certimate-ddns-agent.exe` 与 `agent.json`。首次安装先限制目录权限，再放入程序和配置。已有目录需确认只允许 SYSTEM 和管理员读取、修改。

```powershell
$ErrorActionPreference = 'Stop'
$dir = 'C:\ProgramData\CertimateDDNS'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
icacls.exe $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)'
if ($LASTEXITCODE -ne 0) { throw 'Unable to restrict the DDNS directory' }
Copy-Item -Path .\certimate-ddns-agent.exe -Destination "$dir\certimate-ddns-agent-native.exe"
Copy-Item -Path .\agent.json -Destination $dir
& "$dir\certimate-ddns-agent-native.exe" --config "$dir\agent.json"
if ($LASTEXITCODE -ne 0) { throw 'DDNS report failed' }
$action = "$dir\certimate-ddns-agent-native.exe --config $dir\agent.json"
schtasks.exe /Create /TN CertimateDDNS /SC MINUTE /MO 5 /RU SYSTEM /TR $action /F
if ($LASTEXITCODE -ne 0) { throw 'Unable to register the DDNS task' }
schtasks.exe /Run /TN CertimateDDNS
```

注册任务时 `/F` 会替换同名旧任务。用 `Get-ScheduledTaskInfo -TaskName CertimateDDNS` 查看最近结果和下次运行时间。`LastTaskResult` 为 `0` 表示最近一次执行成功。

## 复测磁盘占用和单次内存峰值

用同一 Rust 版本、目标平台和 release 配置构建。以下命令在 Linux 的仓库根目录执行，使用已登记的测试节点配置重复上报。记录构建版本、目标、文件字节数，以及同一主机上五次执行各自的耗时和峰值 RSS。定时任务空闲时可通过上面的 `MainPID` 核验，预期值为 `0`。

```sh
rustc -Vv
agent=cmd/ddns-agent-native/target/release/certimate-ddns-agent
wc -c < "$agent"
for run in 1 2 3 4 5; do
  /usr/bin/time -f 'elapsed_seconds=%e peak_rss_KiB=%M' "$agent" --config ./agent.json || exit
done
```
