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

- 通过将 Minecraft 官方资源服务器（libraries.minecraft.net、resources.download.minecraft.net）重定向到 CDN 镜像来加速游戏资源下载
- 通过将 maven.minecraftforge.net 重定向到 BMCLAPI 等镜像来加速 Maven 依赖解析
- 在网络受限或速度较慢的环境中进行 URL 重定向优化

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
    - 可执行文件同目录下提供 WinDivert 运行时文件
  - `backend.kind: tun` + `backend.tun.stack: smoltcp`
    - 需要支持 TUN 的桌面操作系统
    - Windows 需要把 `wintun.dll` 放在可执行文件同目录
    - Windows 当前会自动给 TUN 适配器配置 DNS；其他平台仍然需要平台侧 DNS 配置

## 安装与配置

### 1. 安装 WinDivert 驱动

透明代理模式需要 WinDivert 驱动。下载并安装步骤如下：

1. 从 [官方发布页面](https://reqrypt.org/windivert.html) 下载 WinDivert
2. 解压文件：
   - 运行时文件：`WinDivert64.sys`（32 位系统使用 `WinDivert32.sys`）和 `WinDivert.dll`
   - 构建期文件：如果你要从源码编译 AnyMirror，还需要 `WinDivert.lib`
3. 以管理员权限运行透明代理时，驱动会自动加载

**注意：** 运行时文件需要和可执行文件放在同一目录；如果从源码构建，还要保证 `WinDivert.lib` 可用于链接。

### 2. 为 TUN 后端安装 Wintun

如果你在 Windows 上使用 `backend.kind: tun` 运行透明模式，需要从
[Wintun 官网](https://wintun.net/) 下载 `wintun.dll`，并把它放在可执行文件同目录。

**注意：** 这个要求只针对 Windows 下的 TUN 后端；WinDivert 后端不依赖 `wintun.dll`。

### 3. 信任 TLS 证书

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

创建 `config.yml` 文件并编写重定向规则：

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

includes:
  - match:
      prefix: https://libraries.minecraft.net/
    action:
      type: mirror
      upstream:
        url: https://bmclapi2.bangbang93.com/maven/

  - match:
      host: resources.download.minecraft.net
    action:
      type: mirror
      upstream:
        url: https://bmclapi2.bangbang93.com/assets/

  - match:
      exact: https://maven.minecraftforge.net
    action:
      type: mirror
      upstream:
        url: https://bmclapi2.bangbang93.com/maven

  - match:
      exact: https://example.com/api
    action:
      type: mirror
      upstream:
        url: https://api.backend.local
        connect_ip: 10.0.0.5
        connect_host: api.internal.local
        sni: backend.local
        dns:
          mode: doh
          server: https://dns.google/dns-query
```

### 配置字段说明

- **listen：** 代理服务绑定的地址和端口（例如 `127.0.0.1:8787`）
- **tls_port** （可选）：透明模式下本地 TLS 拦截监听端口。如不指定，默认为 `listen_port + 1`。例如 `listen` 为 `127.0.0.1:8787` 时，透明 HTTPS 拦截端口默认为 `8788`，除非在此指定其他端口。
- **backend.kind**：透明拦截后端选择器。如不填写，Windows 默认是 `windivert`，非 Windows 平台默认是 `tun`。`windivert` 是成熟的 Windows 后端；`tun` 是实验性的 TUN 后端入口。
- **backend.dns.listen**：本地 fake-ip DNS 服务地址。WinDivert 和仍然需要 localhost fake DNS 的场景会用到它；`tun + smoltcp` 当前会在 TUN 内直接回答 DNS，不会启动这个本地 listener runtime。
- **backend.dns.fake_ipv4_range**：透明重定向使用的 IPv4 fake-ip 地址池。WinDivert 只会拦截目标地址落在这个网段内的 TCP 连接。
- **backend.dns.fake_ipv6_range**：透明重定向使用的 IPv6 fake-ip 地址池。WinDivert 也会拦截目标地址落在这个网段内的 TCP 连接。
- **backend.dns.record_ttl_secs**：生成 fake A 和 AAAA 记录时使用的 TTL。
- **backend.windivert.layer**：透明模式下 WinDivert 使用的捕获层。`network` 用于本机流量，`network-forward` 用于 WSL、虚拟机或网关场景下的转发流量。
- **backend.tun.name**：TUN 后端使用的设备名。
- **backend.tun.mtu**：TUN 后端使用的 MTU。
- **backend.tun.stack**：TUN 栈选择器。当前默认值是 `smoltcp`。`system` 目前还是 TODO；`smoltcp` 会启用实验性的用户态 TCP/IP 栈后端。
- **backend.tun.platform_dns**：控制 `tun + smoltcp` 的平台 DNS 自动化。`auto` 表示启用平台相关的 DNS 设置；`manual` 表示由用户自己配置。默认值是 Windows 为 `auto`，其他平台为 `manual`。
- **backend.tun.dns_hijack**：`tun + smoltcp` 的可选 DNS 劫持目标列表。`any:53` 表示劫持发往任意目标的 UDP DNS；`tcp://any:53` 表示劫持发往任意目标的 TCP DNS。即使这个列表为空，保留的 TUN 站内 DNS 地址仍然总会被劫持。
- **observability.enable**：可观测子系统总开关。关闭后，AnyMirror 只保留本地 tracing 输出，不会初始化 OTLP trace 导出。
- **observability.telemetry.service_name**：导出 trace 时使用的 OpenTelemetry service name。
- **observability.telemetry.otlp_endpoint**：用于 trace 导出的 OTLP gRPC 端点。
- **includes：** 结构化 `match + action` 规则列表（见下方规则匹配模式）

### 当前 TUN 说明

- `backend.tun.stack: smoltcp` 目前仍然是实验性实现。
- 当前 smoltcp 后端会把接收到的 TCP 流桥接到现有本地 HTTP/TLS listener，并在 TUN 内直接回答 UDP/TCP DNS。
- 默认的 `backend.tun.dns_hijack` 行为等价于：
  - `any:53`
  - `tcp://any:53`
- 当前地址保留模型是：
  - fake-ip 网段中的第一个可用 IPv4 / IPv6 地址：TUN 接口地址
  - 第二个可用 IPv4 / IPv6 地址：TUN DNS 地址
  - fake-ip 分配从第三个可用地址开始
- Windows 当前会自动把 TUN 适配器 DNS 配到保留的 TUN DNS 地址。
- Linux 在 `backend.tun.platform_dns: auto` 下，当前会通过 `resolvectl` 自动配置 TUN 链路 DNS。
- 当前 Linux 自动化走的是 `systemd-resolved` 的链路 DNS 和路由域集成，不是 `nftables` / `iptables` 的 DNS redirect。
- macOS 在当前 CLI 运行时里还没有自动 TUN DNS 配置；建议使用 `manual`，或者改成 `NetworkExtension` 宿主。
- 其他非 Windows 桌面平台目前仍需要你手动把 TUN 接口 DNS 指向这个保留的 TUN DNS 地址。
- QUIC 当前仍然通过丢弃 fake-ip `UDP/443` 来强制客户端回退到 TCP/TLS。
- `system` TUN 栈目前还是 TODO。

### 当前 TUN DNS 设置

- Windows：
  - AnyMirror 会自动给 TUN 适配器配置 DNS。
  - Windows 下的 TUN 后端还要求可执行文件同目录存在 `wintun.dll`。
- Linux：
  - 把 `backend.tun.platform_dns` 设成 `auto` 后，会通过 `resolvectl` 自动配置链路 DNS。
  - 当前 Linux 自动化走的是 `systemd-resolved` 的链路 DNS 和路由域集成，不是 `nftables` / `iptables` 的 DNS redirect。
  - 设成 `manual` 则由你自己配置。
- macOS 和其他非 Windows 桌面平台：
  - AnyMirror 在当前 CLI 运行时中还不会自动配置接口 DNS。
  - 需要你手动把 TUN 接口 DNS 指向保留的 TUN DNS 地址：
    - IPv4：`backend.dns.fake_ipv4_range` 中第二个可用地址
    - IPv6：`backend.dns.fake_ipv6_range` 中第二个可用地址
  - 默认网段下的例子：
    - TUN 接口地址：`198.18.0.1`
    - TUN DNS 地址：`198.18.0.2`
    - fake-ip 分配从 `198.18.0.3` 开始

### 配置监视与热重载

使用 `--watch-config` 启动后，AnyMirror 会轮询当前解析出的配置文件路径，并在文件变化时执行防抖后的原地规则替换或组件级重启。完整的重载计划和当前边界见 [docs/runtime-reload.zh.md](docs/runtime-reload.zh.md)。

### DNS Resolver 模式

AnyMirror 里有两层不同的 DNS 配置：

- `backend.dns.*`：配置透明模式里的 fake-ip DNS 状态。对 WinDivert 来说，这一层也驱动本地 fake DNS listener；对 `tun + smoltcp` 来说，DNS 会在 TUN 内直接回答，而不是通过 localhost listener。
- `upstream.dns.*`：配置某一条镜像规则在连接 upstream 时应当如何解析 upstream host。

当前支持的 `upstream.dns.mode`：

- `system`：使用操作系统当前的 DNS 配置
- `udp`：使用指定的明文 UDP DNS 服务器，此时必须提供 `upstream.dns.server`
- `dot`：使用指定的 DNS-over-TLS 服务器，此时必须提供 `upstream.dns.server`
- `doh`：使用指定的 DNS-over-HTTPS 服务器，此时必须提供 `upstream.dns.server`

- `upstream.dns.server` 示例：
  - `udp`：`1.1.1.1` 或 `1.1.1.1:53`
  - `dot`：`dns.google`、`dns.google:853` 或 `tls://dns.google:853`
  - `doh`：完整 URL，如 `https://dns.google/dns-query`，或者仅填写 host，程序会扩展成 `https://<host>/dns-query`

当前仍不支持：

- 透明模式下对客户端 DoH / DoT 的加密 DNS 拦截

### 规则匹配模式

如果你想看规则引擎的内部模型、加载路径、运行时匹配路径和编译后索引结构，见 [docs/rule-engine.zh.md](docs/rule-engine.zh.md)。

规则引擎现在只使用结构化的 `match + action` 规则：

```yaml
includes:
  - match:
      host: meta.fabricmc.net
    action:
      type: mirror
      upstream:
        url: https://bmclapi2.bangbang93.com/fabric-meta/

  - match:
      host_suffix: neoforged.net
      path_prefix: /releases/
    action:
      type: mirror
      upstream:
        url: https://mirror.example.com/neoforge/

  - match:
      hosts:
        - api.example.com
        - download.example.com
      scheme: https
    action:
      type: direct

  - match:
      host_suffix: telemetry.example.com
    action:
      type: reject
      status: 451
      message: blocked by policy

  - match:
      ip: 203.0.113.10
    action:
      type: direct

  - match:
      ip_cidr: 203.0.113.0/24
      port: 443
    action:
      type: reject
      status: 403
      message: blocked literal IP range
```

结构化匹配字段：

- `match.exact`：匹配一个精确 URL
- `match.prefix`：匹配一个 URL 前缀
- `match.host`：匹配一个域名
- `match.hosts`：匹配一个域名列表中的任意项
- `match.host_suffix`：匹配域名后缀，例如 `example.com`
- `match.ip`：匹配请求 URL 中显式出现的单个 IP host
- `match.ip_cidr`：按 CIDR 网段匹配请求 URL 中显式出现的 IP host
- `match.scheme`：对 host 或 IP 类规则附加 `http` 或 `https` 限制
- `match.port`：对 host 或 IP 类规则附加端口限制
- `match.path_prefix`：对 host 或 IP 类规则附加路径前缀限制

说明：

- `match.ip` 和 `match.ip_cidr` 只匹配 URL host 本身就是 IP 字面量的请求，例如 `https://203.0.113.10/file`
- 规则匹配阶段不会额外把域名解析成真实 IP 再去匹配
- 规则顺序仍然有效。如果多个规则都命中，始终以配置文件里最靠前的规则为准

结构化动作：

- `action.type: mirror`：改写并转发到配置的 upstream
- `action.type: direct`：保留原始目标并直接转发
- `action.type: reject`：本地直接返回拒绝响应，不再访问 upstream

## 架构设计
当前透明代理主链路可以概括成：

```text
FakeDnsServer -> Intercept Backend -> Local Proxy -> Mirror/Direct upstream
```

完整的透明模式架构、组件职责和请求流程见 [docs/architecture.zh.md](docs/architecture.zh.md)。

插件生命周期、`on_request / on_response` 覆写链路，以及响应流转过程见
[docs/plugin-flow.zh.md](docs/plugin-flow.zh.md)。

## 技术细节

- **支持 IPv4 与 IPv6 双栈：**
  透明代理模式自动捕获主机的 IPv4 和 IPv6 TCP 流量，完美适应现代混合网络环境。

- **完整的 HTTP 能力支持：**
  通过 Hyper 引擎实现对所有 HTTP 方法（GET、POST、PUT、DELETE 等）的支持，以及双向高性能流式的请求体和响应体转发。

- **WinDivert 模式（当前拦截后端）：**
  - `Network`：捕获源自或目标为本地主机的流量
  - `NetworkForward`：捕获通过主机转发的流量（为 WSL、虚拟机、USB 网络共享等启用网关功能）

- **Socket 实现：** Tokio 异步 I/O，Hyper 支持 HTTP/2，Rustls 处理 TLS

- **端口分配：**
  - 8787：HTTP 代理监听端口
  - 8788：透明模式使用的本地 TLS 拦截监听端口（默认是 `listen + 1`，也可通过 `tls_port` 指定）

对于显式代理模式，客户端的 HTTP/HTTPS 代理配置都只需要指向 `listen`（例如
`127.0.0.1:8787`）。`tls_port` 不是显式 HTTPS 代理端口。

启用可观测子系统后，同一个 listener 还会额外暴露：

- `GET /state`：当前进程内运行时快照
- `GET /events`：最近的进程内运行时事件

## 当前状态

- 核心的透明 fake-ip 主链已经实现并可用。
- `backend.kind: windivert` 是当前的主要透明后端，已经支持 Windows 下的 `Network` 和 `NetworkForward`。
- `backend.kind: tun` + `backend.tun.stack: smoltcp` 已可用，但仍属于实验性后端。
- 结构化规则、运行时热重载、upstream DNS 控制，以及 QuickJS 插件运行时都已经进入当前 runtime。

## 开发计划

接下来更实际的工作重点会放在可调试性、运行时可观测性和规则易用性上。
像客户端侧 DoH / DoT 拦截这种只影响透明模式、实现复杂度也更高的问题，会明确后置。

### 近期

- 可配置的可观测内核，支持进程内指标、最近事件和运行时状态快照
- 内部可观测 HTTP API，用于暴露 metrics、events、workers 和 reload/runtime 状态
- 流量监控和统计
- 支持规则组，提供共享匹配范围、行为修饰器和标签
- 更强的结构化匹配（`method`、更丰富的 path/query 约束、可选通配 host 规则）
- 内置规则预设与规则集组合
- 插件文件监视与仅插件级的自动重载触发
- 用于静态或模板化 mock 返回，以及 mock 延迟模拟的规则行为配置
- 面向 API 联调的官方 OpenAPI / Swagger 插件工作流

### 中期

- Web UI，用于流量看板、规则调试和运行时巡检
- 显式代理模式下的系统代理管理能力
- 插件事件发射与分发机制

### 长期

- 生产可用的跨平台 TUN/TAP 支持，包括 `system` 栈和平台原生宿主
- DoH / DoT 等客户端侧加密 DNS 的透明拦截支持
