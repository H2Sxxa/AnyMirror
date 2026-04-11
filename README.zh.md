# AnyMirror

[![Codacy Badge](https://app.codacy.com/project/badge/Grade/39c473845ade4c4c9e9e130eee3b3406)](https://app.codacy.com/gh/H2Sxxa/AnyMirror/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/H2Sxxa/AnyMirror)

AnyMirror 是一个用 Rust 编写的高性能流量编排网关。它以透明 L3 代理的方式在 IP 层截获出站网络流量，并把命中的请求交给镜像、直连、拒绝或插件策略处理。在常见 DNS 环境下，这通常不需要做按应用逐个配置的代理设置。

## 原理概述

AnyMirror 现在采用基于 fake-ip 的透明代理链路：

1. **分配 fake-ip：** `FakeDnsServer` 为命中规则的 origin host 返回 fake A/AAAA 记录。
2. **拦截 fake-ip 流量：** `backend.kind: windivert` 会直接截获出站 DNS 和 fake-ip TCP；`backend.kind: tun` + `backend.tun.stack: smoltcp` 会把 fake-ip 流量导入 TUN，并在用户态接受 TCP/UDP。
3. **重定向请求：** WinDivert 会把截获到的流量改写到本地透明代理监听端口，同时共享 NAT 表保存原始目标；smoltcp 后端会把接收到的 TCP 流桥接到现有本地 HTTP/TLS listener，并在 TUN 内直接处理 DNS。
4. **解析转发规则：** 本地代理根据 HTTP Host 或 HTTPS SNI 还原原始 URL，再决定走镜像还是回源直连。
5. **返回响应：** WinDivert 会在响应返回客户端前根据共享 NAT 表还原原始目标四元组；smoltcp 后端则通过用户态协议栈和 TUN 设备把流量送回客户端。

这种方式既保持了对应用透明，也避免了传统“按真实 IP 拦截”方案里“同一真实 IP 下多个 host 串流量”的问题。

## 典型应用场景

- 通过把指定 upstream 重定向到镜像或 CDN 来加速公开下载和依赖获取
- 作为本地显式 HTTP/HTTPS 代理使用，并基于规则执行 `mirror`、`direct`、`respond`、`reject` 和插件动作
- 在支持的平台上以 transparent fake-ip 方式拦截流量，而不需要给每个应用单独配置代理
- 用 `respond` 为选定接口返回本地 mock / stub 响应，包括基于文件的静态返回
- 通过 `/rules/explain` 解释规则冲突和请求路由决策
- 典型例子包括 Minecraft 资源镜像、Maven / Forge 依赖加速，以及本地 API 联调工作流

## 系统要求

### 构建要求

- Rust 工具链 1.70 或以上
- 如果要从源码构建透明模式，需要可用的 WinDivert SDK 文件

### 运行要求

- 显式代理模式：
  - 不依赖 WinDivert
  - 作为普通本地 HTTP/HTTPS 代理运行
- 透明代理模式：
  - 需要管理员/root 权限或等价能力来创建拦截/TUN 资源
  - `backend.kind: windivert`
    - Windows 10 或更高版本
    - 可执行文件同目录下提供 WinDivert 运行时文件；官方 Windows release 已内置 `WinDivert.dll` 和 `WinDivert64.sys`
  - `backend.kind: tun` + `backend.tun.stack: smoltcp`
    - 需要支持 TUN 的桌面操作系统
    - Windows 需要把 `wintun.dll` 放在可执行文件同目录
    - Windows 当前会自动给 TUN 适配器配置 DNS；其他平台仍然需要平台侧 DNS 配置

## 安装与配置

### 1. 下载发布版本

正常使用时，建议优先从最新 GitHub Release 下载，而不是自己从源码构建：

- 从 [GitHub Releases](https://github.com/H2Sxxa/AnyMirror/releases/latest) 下载最新包
- Linux 和 macOS 包会包含 `anymirror` 二进制、`README`、`README.zh`、`LICENSE` 和 `config.example.yml`
- Windows 包还会额外包含 WinDivert 透明后端所需的 `WinDivert.dll` 和 `WinDivert64.sys`
- 如果你准备在 Windows 上使用 TUN 后端，仍然需要另外提供 `wintun.dll`

### 2. 安装 WinDivert 驱动

透明代理模式需要 WinDivert 驱动。下载并安装步骤如下：

1. 从 [官方发布页面](https://reqrypt.org/windivert.html) 下载 WinDivert
2. 解压文件：
   - 运行时文件：`WinDivert64.sys`（32 位系统使用 `WinDivert32.sys`）和 `WinDivert.dll`
   - 构建期文件：如果你要从源码编译 AnyMirror，还需要 `WinDivert.lib`
3. 以管理员权限运行透明代理时，驱动会自动加载

**注意：** 运行时文件需要和可执行文件放在同一目录；如果从源码构建，还要保证 `WinDivert.lib` 可用于链接。

**注意：** 如果你直接使用官方 Windows release 包，通常可以跳过这一步；只有你想自己替换 WinDivert 运行时文件时才需要手动处理。

### 3. 为 TUN 后端安装 Wintun

如果你在 Windows 上使用 `backend.kind: tun` 运行透明模式，需要从
[Wintun 官网](https://wintun.net/) 下载 `wintun.dll`，并把它放在可执行文件同目录。

**注意：** 这个要求只针对 Windows 下的 TUN 后端；WinDivert 后端不依赖 `wintun.dll`。

### 4. 信任 TLS 证书

当 AnyMirror 拦截 HTTPS 流量时，会使用自签名 CA 对流量重新加密。这既包括透明模式下的
HTTPS 拦截，也包括显式代理模式下在 `CONNECT` 之后进入拦截链的 HTTPS 请求。为避免安
全警告：

1. 第一次运行 anymirror 时，它会在工作目录生成 `anymirror_ca.crt` 和 `anymirror_ca.key`
2. 将证书安装到系统或应用中：
   - **Windows 系统信任：** 使用 `certmgr.msc` 或 PowerShell 将 `anymirror_ca.crt` 导入到"受信任的根证书颁发机构"
   - **Java/Maven：** 用以下命令导入 JVM 密钥库：`keytool -import -alias anymirror -file anymirror_ca.crt -keystore %JAVA_HOME%\lib\security\cacerts`
   - **浏览器：** 将证书导入浏览器的受信任 CA 列表

3. 信任证书后，HTTPS 拦截将不显示安全警告

**注意：** 即使不信任证书，代理仍能工作，但应用会显示安全警告或错误。

## 使用方法

下面的示例假定构建后的可执行文件已经以 `anymirror` 的名字加入 `PATH`。

```bash
# 查看帮助信息
anymirror --help

# 显式代理模式（标准 HTTP/HTTPS 代理，监听 8787 端口）
anymirror --mode explicit --config config.yml

# 透明代理模式（拦截本地出站流量）
anymirror --mode transparent --config config.yml

# 监视配置文件，规则变更时自动热重载
anymirror --mode transparent --config config.yml --watch-config

# 透明网关模式：把 config.yml 里的 backend.windivert.layer 改成 network-forward
anymirror --mode transparent --config config.yml
```

在显式代理模式下，客户端的 HTTP 代理和 HTTPS 代理都应填写 `127.0.0.1:8787`。HTTPS 代
理流量同样先进入 `listen`，然后在同一个 socket 上切换到 `CONNECT` 拦截，不存在单独
的显式模式 HTTPS 代理端口。

`--config` 也支持简单 alias。例如 `--config mcdev` 会依次尝试当前目录下的
`config.mcdev.yaml`、`config.mcdev.yml`、`mcdev.yaml`、`mcdev.yml`。

`--watch-config` 支持运行时热重载配置。规则变更会原地生效；其余运行时组件会在同一进程内按受影响范围重启。也就是说进程不退出，但重载仍然不是零中断。更完整的重载行为说明见 [docs/runtime-reload.zh.md](docs/runtime-reload.zh.md)。

### 模式支持范围

当前运行时支持下面这些组合：

| CLI 模式 | 后端 | 平台 | 说明 |
| --- | --- | --- | --- |
| `explicit` | 不需要拦截后端 | 跨平台 | 作为本地 HTTP 代理运行；HTTPS 代理流量同样通过同一个 `listen` 端口进入，并在 `CONNECT` 之后被拦截 |
| `transparent` | `backend.kind: windivert` | 仅 Windows | 使用 fake-ip DNS 加 WinDivert 拦截 |
| `transparent` | `backend.kind: tun` + `backend.tun.stack: smoltcp` | 支持 TUN 的桌面平台，当前仍属实验性 | 使用 TUN 设备加基于 smoltcp 的用户态网络栈 |

透明模式当前有两条后端线：

- `backend.kind: windivert`：成熟的 Windows 后端
- `backend.kind: tun` + `backend.tun.stack: smoltcp`：实验性的用户态网络栈后端，会把接收到的 TCP 流桥接到现有本地 HTTP/TLS listener，并在 TUN 内直接处理 DNS

其中 WinDivert 后端内部还有两种 layer：

- `backend.windivert.layer: network`：拦截本机发起的流量
- `backend.windivert.layer: network-forward`：拦截转发流量，适用于 WSL、虚拟机或局域网网关场景

## 配置文件

建议先从 `config.example.yml` 开始，再复制成 `config.yml` 并按你的环境修改：

```yaml
listen: 127.0.0.1:8787
# tls_port: 8788  # 可选：自定义透明 HTTPS 拦截监听端口（如不指定，默认为 listen_port + 1）
backend:
  kind: windivert              # windivert 或 tun
  dns:
    listen: 127.0.0.1:53        # 本地 fake DNS listener 地址；tun+smoltcp 会在 TUN 内处理 DNS
    fake_ipv4_range: 198.18.0.0/16
    fake_ipv6_range: fd00:198:18::/48
    record_ttl_secs: 60
  windivert:
    layer: network              # network 或 network-forward
  tun:
    name: anymirror-tun         # TUN 设备名
    mtu: 1500
    stack: smoltcp              # system 或 smoltcp（system 当前仍是 TODO）
    platform_dns: auto          # auto 或 manual
    dns_hijack:                 # 可选：tun+smoltcp 的 DNS 劫持目标
      - any:53                 # 劫持 UDP DNS
      - tcp://any:53           # 劫持 TCP DNS
observability:
  enable: false
  telemetry:
    service_name: anymirror
    otlp_endpoint: http://127.0.0.1:4317   # 指向 Jaeger / OTel Collector OTLP gRPC

plugins:
  enabled: false
  workers: 4

includes:
  - match:
      prefix: https://downloads.example.com/packages/
    action:
      type: mirror
      upstream:
        url: https://mirror.example.net/packages/

  - match:
      hosts:
        - api.example.com
        - files.example.com
      scheme: https
    action:
      type: direct

  - match:
      exact: https://api.example.com/health
    action:
      type: respond
      status: 200
      body:
        json:
          ok: true
          source: anymirror

  - match:
      host: telemetry.example.com
    action:
      type: reject
      status: 451
      message: blocked by policy
```

完整的配置字段参考见 [docs/configuration.zh.md](docs/configuration.zh.md)。

### 规则匹配

AnyMirror 使用结构化的 `match + action` 规则。

- matcher：`exact`、`prefix`、`host`、`hosts`、`host_suffix`、`ip`、`ip_cidr`
- action：`mirror`、`direct`、`respond`、`plugin`、`reject`
- `priority` 支持 `xhigh`、`high`、`medium`、`low`、`xlow`，也支持数字
- `spread: true` 表示当前优先级赢家可以继续向更低优先级传播
- `respond` 支持 `body.text`、`body.json`、`body.base64`、`body.file`

完整的规则参考和规则引擎内部模型见 [docs/rule-engine.zh.md](docs/rule-engine.zh.md)。

## 调试接口

- `GET /state`：当前进程内运行时快照
- `GET /events`：最近的进程内运行时事件
- `GET /rules/explain?url=<url>`：按 `priority`、配置顺序和 `spread` 解释候选规则的求值过程

在显式代理模式下，客户端的 HTTP/HTTPS 代理都只需要指向 `listen`（例如 `127.0.0.1:8787`）。`tls_port` 只用于透明模式。

## 当前状态

- 核心的透明 fake-ip 主链已经实现并可用。
- `backend.kind: windivert` 是当前的主要透明后端，已经支持 Windows 下的 `Network` 和 `NetworkForward`。
- `backend.kind: tun` + `backend.tun.stack: smoltcp` 已可用，但仍属于实验性后端。
- 显式模式现在已经支持 HTTP 代理，以及 `CONNECT` 之后的 HTTPS 拦截。
- 结构化规则、运行时热重载、upstream DNS 控制、内建 `respond` 动作，以及 QuickJS 插件运行时都已经进入当前 runtime。
- 可观测子系统已经通过 `GET /state` 和 `GET /events` 暴露进程内运行时快照与最近事件。

## 开发计划

接下来更实际的工作重点会放在可调试性、运行时可观测性和规则易用性上。
像客户端侧 DoH / DoT 拦截这种只影响透明模式、实现复杂度也更高的问题，会明确后置。

### 近期

- 进程内 metrics 与流量统计
- 更完整的内部可观测 HTTP API，用于暴露 metrics、worker 状态，以及更丰富的 reload/runtime 状态
- 支持规则组，提供共享匹配范围、行为修饰器和标签
- 更强的结构化匹配（`method`、更丰富的 path/query 约束、可选通配 host 规则）
- 内置规则预设与规则集组合
- 插件文件监视与仅插件级的自动重载触发
- 用于延迟模拟和更强 `respond` 模板能力的规则行为配置
- 面向 API 联调的官方 OpenAPI / Swagger 插件工作流

### 中期

- Web UI，用于流量看板、规则调试和运行时巡检
- 显式代理模式下的系统代理管理能力
- 插件事件发射与分发机制

### 长期

- 生产可用的跨平台 TUN/TAP 支持，包括 `system` 栈和平台原生宿主
- DoH / DoT 等客户端侧加密 DNS 的透明拦截支持
