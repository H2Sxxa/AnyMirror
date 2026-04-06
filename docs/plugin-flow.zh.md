# 插件流程

这份文档说明 AnyMirror 当前插件的请求与响应流程，包括 `on_load`、`on_compile`、
`on_request` 和 `on_response`。

## 示例场景

假设某个插件在编译阶段产出一条默认动作是：

- `mirror`
- 镜像上游返回体：`i am mirror`

运行时 `on_request` 在某个条件命中后，会把这条编译期动作改成：

- `direct`
- 原始上游返回体：`i am direct`

## 生命周期

```text
配置加载 / 运行时热重载
    |
    v
on_load(config)
    |
    v
plugin state
    |
    v
on_compile(config + state)
    |
    v
program.rules
```

## 请求 / 响应主流程

```text
请求进入 AnyMirror
    |
    v
主规则引擎
    |
    +-- 没有命中 plugin 规则
    |      |
    |      v
    |   走普通 mirror/direct/reject 流程
    |
    `-- 命中 plugin 规则
           |
           v
      构造 PluginRequestContext(request)
           |
           v
      匹配 plugin program.rules
           |
           +-- 没有命中 plugin program rule
           |      |
           |      +-- 没有 on_request 或 on_request 返回 null
           |      |      |
           |      |      v
           |      |   resolved_action = direct
           |      |
           |      `-- on_request 返回 action override
           |             |
           |             v
           |          resolved_action = 返回值
           |
           `-- 命中 plugin program rule
                  |
                  v
             matched.action = 编译期 action
                  |
                  +-- 没有 on_request 或 on_request 返回 null
                  |      |
                  |      v
                  |   resolved_action = matched.action
                  |
                  `-- on_request 返回 action override
                         |
                         v
                      resolved_action = 返回值
```

## 上游分支

```text
resolved_action
    |
    +-- reject
    |      |
    |      v
    |   直接返回本地 reject 响应
    |   on_response 不执行
    |
    +-- direct
    |      |
    |      v
    |   请求发往原始上游
    |      |
    |      v
    |   上游返回体 = "i am direct"
    |      |
    |      v
    |   on_response(request, matched, resolved_action=direct, response)
    |
    `-- mirror
           |
           v
        请求发往镜像上游
           |
           v
        上游返回体 = "i am mirror"
           |
           v
        on_response(request, matched, resolved_action=mirror, response)
```

## `on_response` 能看到的数据

`on_response` 当前会拿到：

- `request`
  - 已经应用了 `on_request` request patch 之后的最终请求视图
- `matched`
  - 原始编译期 plugin 规则命中结果
- `resolved_action`
  - 经过 `on_request` override 之后，实际被执行的最终动作
- `response`
  - 上游真实返回、尚未回给客户端前的缓冲响应

这意味着 `on_response` 可以同时区分：

- 编译期规则原本想做什么
- `on_request` 后来把它改成了什么
- 上游最终真实返回了什么

## Mirror -> Direct Override 示例

```text
编译期 plugin rule:
    matched.action = mirror

on_request 条件命中后:
    resolved_action = direct

真实上游路径:
    original upstream -> "i am direct"

on_response 看到的是:
    matched.action   = mirror
    resolved_action  = direct
    response.body    = "i am direct"
```
