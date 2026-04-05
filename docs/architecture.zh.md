# 架构设计

这份文档说明 AnyMirror 当前透明模式的整体架构。

## 透明代理主链路

```text
                      +----------------------+
                      |      AppConfig       |
                      | rules / dns / ports  |
                      +----------+-----------+
                                 |
                                 v
                      +----------+-----------+
                      |    LiveRuleSet       |
                      | CompiledRuleIndex    |
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
              +--------+---------+   +--+------------------+
              |    Supervisors   |   |      Workers        |
              | listener/dns/    |   | config watch / DNS  |
              | intercept        |   | server / WinDivert  |
              +--------+---------+   +---------------------+
                       |
     +-----------------+-------------------------------+
     |                 |                               |
     v                 v                               v
+----+---------+  +----+---------+            +--------+---------+
| Local Proxy  |  | FakeDnsServer |            | Intercept Backend |
| HTTP/TLS     |  | shared/dns    |            | 当前实现: WinDivert|
+----+---------+  +----+---------+            +--------+---------+
     |                 |                               |
     |                 |                               v
     |                 |                    +----------+----------+
     |                 |                    | DNS UDP responder   |
     |                 |                    | DNS TCP redirect    |
     |                 |                    | Fake-IP TCP redirect|
     |                 |                    | QUIC drop           |
     |                 |                    | Proxy response rw   |
     |                 |                    +----------+----------+
     |                 |                               |
     +-----------------+-------------------------------+
                                 |
                                 v
                      +----------+-----------+
                      |      Shared NAT      |
                      |   traffic/shared     |
                      +----------+-----------+
                                 |
                                 v
                      +----------+-----------+
                      |   Mirror / Direct    |
                      |      upstream 决策    |
                      +----------+-----------+
                                 |
                   +-------------+-------------+
                   |                           |
                   v                           v
            +------+-------+            +------+------+ 
            | Mirror Upstream|          | Original Up |
            +----------------+          +-------------+
```

## 职责划分

- `FakeDnsServer`
  - 为命中 fake-ip 策略的 host 分配 fake IPv4 / IPv6。
  - 回答 fake DNS 请求，并通过热更新后的规则集判断某个 host 是否应该进入 fake-ip 流程。
- `Intercept Backend`
  - 负责数据包拦截。
  - 当前实现是 WinDivert。
  - 这一层的设计目标是未来可替换成 TUN/TAP 后端。
- `Shared NAT`
  - 维护 `(client_ip, client_port) -> (original_destination_ip, original_destination_port)` 映射。
  - 让拦截后端能在响应返回客户端前还原原始目标元组。
- `Local Proxy`
  - 根据 HTTP Host 或 HTTPS SNI 还原原始请求目标。
  - 执行规则匹配，并决定是走镜像还是回源直连。
- `LiveRuleSet`
  - 在代理路径和 fake DNS 路径之间共享编译后的规则引擎。
  - 支持进程内热替换。

## 请求流程

1. 应用先解析一个命中 fake-ip 策略的域名。
2. `FakeDnsServer` 从配置的地址池里返回 fake IPv4 或 fake IPv6。
3. 拦截后端截获发往 fake-ip 的 TCP 连接，并将其重定向到本地代理监听端口。
4. 本地代理还原原始 URL，然后执行规则匹配。
5. 命中规则则转发到镜像；未命中则回源直连。
6. 共享 NAT 让拦截后端可以在响应返回客户端前，把代理响应还原成原始目标连接。

## 说明

- 透明模式当前只支持 WinDivert 拦截后端。
- QUIC 当前不会被代理转发。命中 fake-ip 的 QUIC 流量会被丢弃，以强制客户端回退到 TCP/TLS。
- 当前架构是 `FakeDnsServer + Intercept Backend + Local Proxy`，并不是完整用户态 TCP/IP 网络栈。
