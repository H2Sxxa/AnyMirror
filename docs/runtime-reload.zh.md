# 运行时热重载

这份文档说明 `--watch-config` 的工作方式，以及配置变化时哪些部分会被重载。

## 概览

使用 `--watch-config` 启动后，AnyMirror 会：

1. 轮询当前解析出的配置文件路径
2. 等待文件的最后修改时间在一个短暂的防抖窗口内稳定下来
3. 重新加载配置
4. 根据变化内容，执行原地规则替换或组件重启

进程本身不会退出，但运行时热重载并不是零中断。

## 原地规则热替换

下面这些变化会直接原地生效，不需要重启运行时组件：

- `includes`
- `rules`

新的 `RuleSet` 会重新编译，然后原子替换到 `LiveRuleSet` 中。

## 组件级重启

当前的重载计划是按组件粒度执行的：

- `listen`
  - 显式模式：重启 HTTP listener
  - 透明模式：重启 HTTP listener 和拦截后端
- `tls_port`
  - 重启 TLS listener 和拦截后端
- `backend.dns.listen`
  - 重启 fake DNS 状态/runtime 和拦截后端
- `backend.dns.fake_ipv4_range`
  - 重启 fake DNS 状态/runtime 和拦截后端
- `backend.dns.fake_ipv6_range`
  - 重启 fake DNS 状态/runtime 和拦截后端
- `backend.dns.record_ttl_secs`
  - 重启 fake DNS 状态/runtime 和拦截后端
- `backend.kind`
  - 只重启拦截后端
- `backend.windivert.*`
  - 只重启拦截后端
- `backend.tun.*`
  - 只重启拦截后端

## 运行时模型

当前运行时使用：

- supervisors 管理长期组件
- workers 管理后台任务
- 在同一进程内按受影响范围顺序重启组件

这意味着：

- 没受影响的组件会继续存活
- 受影响的组件会在同一进程里先关闭再启动

## 当前边界

- 重载仍然是顺序重建，不是 generation overlap。
- 组件重启时可能会有一个很短的中断窗口。
- fake DNS 状态/runtime 或拦截后端重建时，已有透明连接可能会被重置。
- 当前仍然不支持对客户端 DoH / DoT 做加密 DNS 拦截。

## 相关文件

- [`src/watch.rs`](/c:/WorkSpace/rust/anymirror/src/watch.rs)
- [`src/proxy/runtime.rs`](/c:/WorkSpace/rust/anymirror/src/proxy/runtime.rs)
- [`src/supervisors`](/c:/WorkSpace/rust/anymirror/src/supervisors)
