# 配置说明

这份文档是 `config.yml` 的字段参考。

## 核心字段

- `listen`：服务绑定地址和端口，例如 `127.0.0.1:8787`
- `tls_port`：
  透明模式下本地 TLS 拦截 listener 的端口；如不指定，默认为
  `listen_port + 1`
- `backend.kind`：
  透明拦截后端选择器；Windows 默认 `windivert`，非 Windows 默认 `tun`
- `includes`：
  结构化 `match + action` 规则列表
- `observability.enable`：
  可观测子系统总开关
- `observability.telemetry.service_name`：
  导出 trace 时使用的 OpenTelemetry service name
- `observability.telemetry.otlp_endpoint`：
  导出 trace 时使用的 OTLP gRPC 端点

## 后端 DNS

- `backend.dns.listen`：
  本地 fake-ip DNS listener 地址；WinDivert 和仍然需要 localhost fake DNS
  的场景会使用它
- `backend.dns.fake_ipv4_range`：
  透明重定向使用的 IPv4 fake-ip 地址池
- `backend.dns.fake_ipv6_range`：
  透明重定向使用的 IPv6 fake-ip 地址池
- `backend.dns.record_ttl_secs`：
  生成 fake A / AAAA 记录时使用的 TTL

## WinDivert 后端

- `backend.windivert.layer`：
  透明模式下使用的 WinDivert 捕获层
  - `network`：本机流量
  - `network-forward`：转发流量，例如 WSL、虚拟机或网关场景

## TUN 后端

- `backend.tun.name`：TUN 设备名
- `backend.tun.mtu`：TUN MTU
- `backend.tun.stack`：
  TUN 栈选择器；当前默认是 `smoltcp`，`system` 仍然是 TODO
- `backend.tun.platform_dns`：
  `tun + smoltcp` 的平台 DNS 自动化模式
  - Windows 默认：`auto`
  - 其他平台默认：`manual`
- `backend.tun.dns_hijack`：
  `tun + smoltcp` 的可选 DNS 劫持目标列表

当前说明：

- `backend.tun.stack: smoltcp` 仍然属于实验性实现
- smoltcp 后端会把接收到的 TCP 流桥接到本地 HTTP/TLS listener，并在 TUN 内
  直接处理 UDP/TCP DNS
- 默认 DNS 劫持行为等价于：
  - `any:53`
  - `tcp://any:53`
- 透明模式下对客户端 DoH / DoT 的加密 DNS 拦截当前仍不支持

## Upstream DNS

AnyMirror 里有两层 DNS 配置：

- `backend.dns.*`：透明模式下的 fake-ip DNS 状态
- `upstream.dns.*`：单条镜像规则的 upstream 解析策略

当前支持的 `upstream.dns.mode`：

- `system`
- `udp`
- `dot`
- `doh`

`upstream.dns.server` 示例：

- `udp`：`1.1.1.1` 或 `1.1.1.1:53`
- `dot`：`dns.google`、`dns.google:853` 或 `tls://dns.google:853`
- `doh`：完整 URL，例如 `https://dns.google/dns-query`

## 配置监视与热重载

`--watch-config` 会在运行时热重载配置文件：

- 规则会原地替换
- 受影响的运行时组件会在同一进程内重启
- 重载仍然不是零中断

更完整的重载行为和边界见 [runtime-reload.zh.md](./runtime-reload.zh.md)。
