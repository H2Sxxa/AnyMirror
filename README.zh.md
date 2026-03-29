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

includes:
  # 前缀匹配（以 / 结尾的 URL 默认方式）
  - from: https://libraries.minecraft.net/
    to: https://bmclapi2.bangbang93.com/maven
    
  # 前缀匹配（显式指定）
  - kind: prefix
    from: https://resources.download.minecraft.net/
    to: https://bmclapi2.bangbang93.com/assets/
    
  # 精确匹配（不以 / 结尾的 URL 默认方式）
  - kind: exact
    from: https://maven.minecraftforge.net
    to: https://bmclapi2.bangbang93.com/maven
```

### 配置字段说明

- **listen：** 代理服务绑定的地址和端口（例如 `127.0.0.1:8787`）
- **tls_port** （可选）：自定义 HTTPS 代理端口。如不指定，默认为 `listen_port + 1`。例如 `listen` 为 `127.0.0.1:8787` 时，HTTPS 端口默认为 `8788`，除非在此指定其他端口。
- **includes：** URL 重定向规则列表（见下方规则匹配模式）

### 规则匹配模式

- **prefix：** 匹配任何路径以 "from" 路径开头的请求。适用于重定向整个目录树。查询字符串会被保留。
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

- **WinDivert 模式：**
  - `Network`：捕获源自或目标为本地主机的流量
  - `NetworkForward`：捕获通过主机转发的流量（为 WSL、虚拟机、USB 网络共享等启用网关功能）

- **Socket 实现：** Tokio 异步 I/O，Hyper 支持 HTTP/2，Rustls 处理 TLS

- **端口分配：**
  - 8787：HTTP 代理监听端口
  - 8788：HTTPS 代理监听端口（自动为 443 端口目标选中）

## 开发计划

- [x] 基于 WinDivert 的 L3 数据包拦截（Network 和 NetworkForward 层）
- [x] HTTPS 请求的 SNI 提取
- [x] HTTP 请求的 Host 头提取
- [x] 基于 Tokio 和 Rustls 的异步 Socket 处理
- [x] 基于 clap 的命令行界面
- [ ] 配置文件监视和热重载（配置文件变化时自动重新加载）
- [ ] TUN/TAP 设备支持，用于跨平台部署（macOS、Linux），集成用户态 TCP/IP 协议栈
- [ ] 高级规则匹配（正则表达式、通配符、HTTP 版本/方法筛选）
- [ ] 流量监控和统计
