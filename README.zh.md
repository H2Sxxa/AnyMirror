# AnyMirror

AnyMirror 是一款用 Rust 编写的透明 L3 代理工具，可以在网络层截获并重定向指定的 URL 请求到镜像服务器，无需在客户端进行任何配置。

## 原理概述

AnyMirror 现在采用基于 fake-ip 的透明代理链路：

1. **分配 fake-ip：** `FakeDnsServer` 为命中规则的 origin host 返回 fake A/AAAA 记录。
2. **拦截 fake-ip 流量：** 当前的拦截后端是 WinDivert，它只处理 DNS 查询和目标地址落在 fake-ip 网段中的 TCP 流量。
3. **执行 NAT 重定向：** 被截获的连接会被改写到本地透明代理监听端口，同时共享 NAT 表会保存原始目标信息。
4. **解析转发规则：** 本地代理根据 HTTP Host 或 HTTPS SNI 还原原始 URL，再决定走镜像还是回源直连。
5. **还原响应：** 拦截后端在响应返回客户端之前，根据共享 NAT 表把代理响应改回原始目标四元组。

这种方式既保持了对应用透明，也避免了传统“按真实 IP 拦截”方案里“同一真实 IP 下多个 host 串流量”的问题。

## 典型应用场景

- 通过将 Minecraft 官方资源服务器（libraries.minecraft.net、resources.download.minecraft.net）重定向到 CDN 镜像来加速游戏资源下载
- 通过将 maven.minecraftforge.net 重定向到 BMCLAPI 等镜像来加速 Maven 依赖解析
- 在网络受限或速度较慢的环境中进行 URL 重定向优化

## 系统要求

- Rust 工具链 1.70 或以上
- 显式代理模式：
  - 不依赖 WinDivert
  - 作为普通本地 HTTP/HTTPS 代理运行
- 透明代理模式：
  - Windows 10 或更高版本
  - 管理员权限
  - 可执行文件同目录下提供 WinDivert 驱动文件

## 安装与配置

### 1. 安装 WinDivert 驱动

透明代理模式需要 WinDivert 驱动。下载并安装步骤如下：

1. 从 [官方发布页面](https://reqrypt.org/windivert.html) 下载 WinDivert
2. 解压文件，需要以下文件放在项目目录中：
   - `WinDivert64.sys`（32 位系统使用 `WinDivert32.sys`）- 内核驱动
   - `WinDivert.dll` - 运行时库
   - `WinDivert.lib` - 导入库（编译时需要）
3. 以管理员权限运行透明代理时，驱动会自动加载

**注意：** 将所有三个文件放在项目根目录，与可执行文件相同的目录。

### 2. 信任 TLS 证书

在透明代理模式下，anymirror 拦截 HTTPS 流量并用自签名证书重新加密。为避免安全警告：

1. 第一次运行 anymirror 时，它会在工作目录生成 `anymirror.crt` 和 `anymirror.key`
2. 将证书安装到系统或应用中：
   - **Windows 系统信任：** 使用 `certmgr.msc` 或 PowerShell 将 `anymirror.crt` 导入到"受信任的根证书颁发机构"
   - **Java/Maven：** 用以下命令导入 JVM 密钥库：`keytool -import -alias anymirror -file anymirror.crt -keystore %JAVA_HOME%\lib\security\cacerts`
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

`--config` 也支持简单 alias。例如 `--config mcdev` 会依次尝试当前目录下的
`config.mcdev.yaml`、`config.mcdev.yml`、`mcdev.yaml`、`mcdev.yml`。

`--watch-config` 目前只会热重载规则集（`includes` / `rules`）。监听端口和 backend
相关配置变更后，仍然需要重启进程。

### 模式支持范围

当前运行时支持下面这些组合：

| CLI 模式 | 后端 | 平台 | 说明 |
| --- | --- | --- | --- |
| `explicit` | 不需要拦截后端 | 跨平台 | 作为标准本地 HTTP/HTTPS 代理运行 |
| `transparent` | `backend.windivert` | 仅 Windows | 使用 fake-ip DNS 加 WinDivert 拦截 |

透明模式当前只支持 WinDivert 拦截后端。透明模式内部还有两种 WinDivert layer：

- `backend.windivert.layer: network`：拦截本机发起的流量
- `backend.windivert.layer: network-forward`：拦截转发流量，适用于 WSL、虚拟机或局域网网关场景

在非 Windows 平台上，透明模式不可用，程序会直接返回明确错误。

## 配置文件

创建 `config.yml` 文件并编写重定向规则：

```yaml
listen: 127.0.0.1:8787
# tls_port: 8788  # 可选：自定义 HTTPS 代理端口（如不指定，默认为 listen_port + 1）
backend:
  dns:
    listen: 127.0.0.1:15353     # 本地 fake-ip DNS 服务监听地址，Windows 上 5353 往往会被 mDNS 占用
    fake_ipv4_range: 198.18.0.0/16
    fake_ipv6_range: fd00:198:18::/48
    record_ttl_secs: 60
  windivert:
    layer: network              # network 或 network-forward

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
- **tls_port** （可选）：自定义 HTTPS 代理端口。如不指定，默认为 `listen_port + 1`。例如 `listen` 为 `127.0.0.1:8787` 时，HTTPS 端口默认为 `8788`，除非在此指定其他端口。
- **backend.dns.listen**：本地 fake-ip DNS 服务地址。透明 fake-ip 模式要求系统或应用的 DNS 查询发到这里。
- **backend.dns.fake_ipv4_range**：透明重定向使用的 IPv4 fake-ip 地址池。WinDivert 只会拦截目标地址落在这个网段内的 TCP 连接。
- **backend.dns.fake_ipv6_range**：透明重定向使用的 IPv6 fake-ip 地址池。WinDivert 也会拦截目标地址落在这个网段内的 TCP 连接。
- **backend.dns.record_ttl_secs**：生成 fake A 和 AAAA 记录时使用的 TTL。
- **backend.windivert.layer**：透明模式下 WinDivert 使用的捕获层。`network` 用于本机流量，`network-forward` 用于 WSL、虚拟机或网关场景下的转发流量。
- **includes：** 结构化 `match + action` 规则列表（见下方规则匹配模式）

### 配置监视与热重载

使用 `--watch-config` 启动后，AnyMirror 会轮询当前解析出的配置文件路径，并在文件变化时原地热重载规则集。为避免编辑器连续写入带来的抖动，watcher 会等待文件的最后修改时间稳定一小段时间后再执行重载。

- 可立即热生效：
  - `includes`
  - `rules`
- 仍需重启进程：
  - `listen`
  - `tls_port`
  - `backend.dns.*`
  - `backend.windivert.*`

透明模式下，本地代理和 `FakeDnsServer` 会共用这份热更新后的规则，因此规则变化会同时影响请求匹配和 fake-ip DNS 判定。

### DNS Resolver 模式

AnyMirror 里有两层不同的 DNS 配置：

- `backend.dns.*`：配置透明模式使用的本地 fake-ip DNS 服务。这一层不是“上游解析器模式”的开关。
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
```

结构化匹配字段：

- `match.exact`：匹配一个精确 URL
- `match.prefix`：匹配一个 URL 前缀
- `match.host`：匹配一个域名
- `match.hosts`：匹配一个域名列表中的任意项
- `match.host_suffix`：匹配域名后缀，例如 `example.com`
- `match.scheme`：对 host 类规则附加 `http` 或 `https` 限制
- `match.port`：对 host 类规则附加端口限制
- `match.path_prefix`：对 host 类规则附加路径前缀限制

结构化动作：

- `action.type: mirror`：改写并转发到配置的 upstream
- `action.type: direct`：保留原始目标并直接转发
- `action.type: reject`：本地直接返回拒绝响应，不再访问 upstream

## 架构设计

### 透明代理主链路

```text
                      +----------------------+
                      |      AppConfig       |
                      | rules / dns / ports  |
                      +----------+-----------+
                                 |
                                 v
+-----------------------------------------------------------+
|                    Transparent Runtime                    |
|             proxy::runtime::serve_transparent             |
+----------------------+----------------+-------------------+
                       |                |
                       |                |
                       v                v
             +---------+----+    +------+------------------+
             | FakeDnsServer |    |   Intercept Backend    |
             | shared/dns    |    |   当前实现: WinDivert  |
             +---------+----+    +------+------------------+
                       |                |
                       |                |
                       |                v
                       |      +---------+------------------+
                       |      |  DNS UDP responder         |
                       |      |  DNS TCP redirect          |
                       |      |  Fake-IP TCP redirect      |
                       |      |  QUIC drop policy          |
                       |      |  Proxy response rewrite    |
                       |      +---------+------------------+
                       |                |
                       |                v
                       |      +---------+------------------+
                       |      |        Shared NAT          |
                       |      |     traffic/shared/nat     |
                       |      +---------+------------------+
                       |                |
                       +----------------+
                                        |
                                        v
                        +---------------+---------------+
                        |     Local Transparent Proxy   |
                        | HTTP :8787 / TLS :8788        |
                        +---------------+---------------+
                                        |
                                        v
                             +----------+----------+
                             |    Rule Resolution  |
                             |  mirror or direct   |
                             +----------+----------+
                                        |
                      +-----------------+-----------------+
                      |                                   |
                      v                                   v
               +------+-------+                    +------+------+
               | Mirror Upstream|                  | Original Up |
               +----------------+                  +-------------+
```

### 职责划分

- **FakeDnsServer：** 负责为命中规则的 origin host 分配 fake-ip，并生成 DNS 响应。
- **Intercept Backend：** 负责做数据包拦截。当前实现是 WinDivert，后续也可以替换成 TUN/TAP 后端。
- **Shared NAT：** 维护 `(client_ip, client_port) -> (original_destination_ip, original_destination_port)` 映射，用于把代理响应改回原始目标。
- **Local Transparent Proxy：** 根据 HTTP Host 或 HTTPS SNI 还原原始请求目标，并决定是走镜像还是回源直连。

### 请求流程

1. 应用先解析某个命中规则的域名。
2. `FakeDnsServer` 返回来自 fake-ip 地址池的 fake IPv4 或 fake IPv6。
3. 拦截后端截获发往 fake-ip 的 TCP 连接，并将其重定向到本地代理监听端口。
4. 本地代理还原原始 URL，然后执行规则匹配。
5. 命中规则则转发到镜像，不命中则回源直连。
6. 共享 NAT 让拦截后端可以在响应返回客户端前，把代理响应还原成原始目标连接。

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
  - 8788：HTTPS 代理监听端口（自动为 443 端口目标选中）

## 开发计划

- [x] 基于 WinDivert 的拦截后端（`Network` 和 `NetworkForward`）用于 Windows 透明流量捕获
- [x] 支持 IPv4 与 IPv6 的 Fake-IP DNS 主链
- [x] DNS UDP 就地响应与 DNS-over-TCP 重定向到本地 fake DNS 服务
- [x] 共享 NAT，用于透明请求重定向与代理响应还原
- [x] 基于 Rustls 动态证书的透明 HTTP / HTTPS 拦截
- [x] 基于 Hyper 的高性能 upstream 执行与完整请求体转发
- [x] 结构化规则引擎，支持 `exact`、`prefix`、`host`、`hosts`、`host_suffix`
- [x] 结构化规则动作，支持 `mirror`、`direct`、`reject`
- [x] 可扩展的 upstream 配置（`connect_ip`、`connect_host`、`sni` 与自定义 upstream DNS）
- [x] CLI 启动参数支持配置 alias fallback（如 `--config mcdev` 自动解析到 `config.mcdev.yml`）
- [x] 配置文件监视与规则热重载（通过 `--watch-config`）
- [ ] 监听器、Fake DNS 服务和拦截后端的完整运行时热重载
- [ ] TUN/TAP 设备支持，用于跨平台部署（macOS、Linux），集成用户态 TCP/IP 协议栈
- [ ] DoH / DoT 等加密 DNS 的拦截支持
- [ ] 高级规则匹配（正则表达式、通配主机模式、HTTP 版本/方法筛选）
- [ ] 内置规则预设与规则集组合
- [ ] 流量监控和统计
