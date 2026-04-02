# AnyMirror

AnyMirror 是一款用 Rust 编写的透明 L3 代理工具，可以在网络层截获并重定向指定的 URL 请求到镜像服务器，无需在客户端进行任何配置。

## 原理概述

AnyMirror 在第 3 层（网络层）工作，流程如下：

1. **拦截数据包：** 使用 WinDivert 驱动程序捕获所有符合过滤规则的出站 TCP 流量。
2. **提取主机名：** 对于 HTTPS 请求从 TLS ClientHello 中提取 SNI；对于 HTTP 请求提取 Host 头。
3. **执行 NAT 重定向：** 修改捕获数据包的目标 IP 和端口，然后重新注入到本地网络栈，伪装成来自本机代理服务的请求。
4. **处理响应：** 维护 NAT 转换表，将来自代理的响应反向映射并还原原始目标信息。

这种方式对应用程序完全透明，无需任何客户端配置、代理设置或环境变量修改。

## 典型应用场景

- 通过将 Minecraft 官方资源服务器（libraries.minecraft.net、resources.download.minecraft.net）重定向到 CDN 镜像来加速游戏资源下载
- 通过将 maven.minecraftforge.net 重定向到 BMCLAPI 等镜像来加速 Maven 依赖解析
- 在网络受限或速度较慢的环境中进行 URL 重定向优化

## 系统要求

- Windows 10 或更高版本（基于 WinDivert 实现）
- 管理员权限（需要加载 WinDivert 驱动程序并捕获网络流量）
- Rust 工具链 1.70 或以上

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

```bash
# 查看帮助信息
cargo run -- --help

# 显式代理模式（标准 HTTP/HTTPS 代理，监听 8787 端口）
cargo run -- --mode explicit --config config.yml

# 透明代理模式（拦截本地出站流量）
cargo run -- --mode transparent --config config.yml

# 透明网关模式（拦截来自 LAN/WSL/虚拟机的转发流量）
cargo run -- --mode transparent --layer network-forward --config config.yml
```

## 配置文件

创建 `config.yml` 文件并编写重定向规则：

```yaml
listen: 127.0.0.1:8787
# tls_port: 8788  # 可选：自定义 HTTPS 代理端口（如不指定，默认为 listen_port + 1）
windivert:
  hot_reload: false # 可选：保持请求过滤规则尽量收敛，并在 DNS 目标 IP 变化时热切换请求捕获代际

includes:
  # 前缀匹配（以 / 结尾的 URL 默认方式）
  - origin: https://libraries.minecraft.net/
    upstream:
      url: https://bmclapi2.bangbang93.com/maven

  # 前缀匹配（显式指定）
  - kind: prefix
    origin: https://resources.download.minecraft.net/
    upstream:
      url: https://bmclapi2.bangbang93.com/assets/

  # 精确匹配（不以 / 结尾的 URL 默认方式）
  - kind: exact
    origin: https://maven.minecraftforge.net
    upstream:
      url: https://bmclapi2.bangbang93.com/maven
  # 高级 Upstream 重写配置 (SNI, Custom DNS, IP mapping)
  - kind: exact
    origin: https://example.com/api
    upstream:
      url: https://api.backend.local
      connect_ip: 10.0.0.5     # 强制将流量发送到指定的 IP
      connect_host: api.internal.local # 覆盖 DNS 解析的目标域名
      sni: backend.local       # 覆盖 TLS 握手时的 SNI 域名
      dns:
        mode: doh              # DNS 解析模式: system, udp, 或 doh
        server: https://dns.google/dns-query # DoH 服务器（如果 mode 是 udp，则填标准 DNS IP）
```

### 配置字段说明

- **listen：** 代理服务绑定的地址和端口（例如 `127.0.0.1:8787`）
- **tls_port** （可选）：自定义 HTTPS 代理端口。如不指定，默认为 `listen_port + 1`。例如 `listen` 为 `127.0.0.1:8787` 时，HTTPS 端口默认为 `8788`，除非在此指定其他端口。
- **windivert.hot_reload** （可选）：启用后，透明模式会使用由 DNS 驱动的目标 IP 存储，并在活动目标 IP 集合变化时经过宽限期热切换新的 WinDivert 请求捕获代际，而不是让单个长期句柄不断变宽或无限累积。
- **includes：** URL 重定向规则列表（见下方规则匹配模式）

### 规则匹配模式

- **prefix：** 匹配任何路径以 "origin" 路径开头的请求。适用于重定向整个目录树。查询字符串会被保留。
- **exact：** 仅匹配完全相同的 URL（方案、域名、端口、路径和查询必须全部匹配）。对于不以 `/` 结尾的 URL，这是默认模式。

如果省略 `kind` 字段，系统会自动判断：以 `/` 结尾的 URL 默认使用 `prefix` 模式，其他 URL 默认使用 `exact` 模式。代理透明地处理 HTTP 和 HTTPS 流量，提取原始主机名并改写请求。

## 架构设计

### L3 代理实现

透明代理使用 WinDivert 在 IP 层截获数据包：

- **出站重定向：** 应用程序发送对 blocked.example.com:443 的请求时，WinDivert 在数据包离开主机前将其截获。代理修改目标 IP 为 127.0.0.1、目标端口为 8788，然后重新注入网络栈。本地代理服务在该端口接收连接。

- **入站响应处理：** 代理响应返回时，WinDivert 识别这是代理服务的响应，反向执行 NAT 转换，在数据包返回客户端应用之前还原原始目标信息。

- **连接隔离：** 通过 NAT 转换表维护 (client_ip, client_port) 与 (original_destination_ip, original_destination_port) 的映射关系，确保响应正确路由。

### 主机名识别

- **HTTP 请求：** 代理从 Host 头提取原始目标。
- **HTTPS 请求：** 代理从 TLS ClientHello 握手数据包中提取 SNI（服务器名称指示），在加密连接建立前进行。

两种提取方式都在数据包级别工作，不需要在初始截获阶段进行 TLS 解密。

## 技术细节

- **支持 IPv4 与 IPv6 双栈：**
  透明代理模式自动捕获主机的 IPv4 和 IPv6 TCP 流量，完美适应现代混合网络环境。

- **完整的 HTTP 能力支持：**
  通过 Hyper 引擎实现对所有 HTTP 方法（GET、POST、PUT、DELETE 等）的支持，以及双向高性能流式的请求体和响应体转发。

- **WinDivert 模式：**
  - `Network`：捕获源自或目标为本地主机的流量
  - `NetworkForward`：捕获通过主机转发的流量（为 WSL、虚拟机、USB 网络共享等启用网关功能）

- **Socket 实现：** Tokio 异步 I/O，Hyper 支持 HTTP/2，Rustls 处理 TLS

- **端口分配：**
  - 8787：HTTP 代理监听端口
  - 8788：HTTPS 代理监听端口（自动为 443 端口目标选中）

## 开发计划

- [x] 基于 WinDivert 的 L3 数据包拦截（IPv4 及 IPv6，包含 Network 和 NetworkForward 层）
- [x] HTTPS 请求的 SNI 提取
- [x] HTTP 请求的 Host 头提取
- [x] 高性能的 Hyper 引擎重构（支持全 HTTP 方法与上下行 Request Body 透传）
- [x] 基于 Tokio 和原生 Rustls 的完全异步 Socket 网络栈
- [x] 可扩展的高级 Upstream 配置 (`connect_ip`、`connect_host`、`sni` 以及 `DoH` 自定义 DNS)
- [x] 基于 clap 的命令行界面
- [ ] 配置文件监视和热重载（配置文件变化时自动重新加载）
- [ ] TUN/TAP 设备支持，用于跨平台部署（macOS、Linux），集成用户态 TCP/IP 协议栈
- [ ] 高级规则匹配（正则表达式、通配符、HTTP 版本/方法筛选）
- [ ] 流量监控和统计
