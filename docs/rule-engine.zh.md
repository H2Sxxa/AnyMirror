# 规则引擎

这份文档说明 AnyMirror 的规则是如何被加载、编译，以及在运行时如何匹配的。

## 分层关系

```text
RuleSchema
  -> Rule
  -> RuleSet
  -> LiveRuleSet
```

- `RuleSchema`
  - 文件：[`src/rules/schema.rs`](../src/rules/schema.rs)
  - 面向 YAML 的可读配置结构。
- `Rule`
  - 文件：[`src/rules/model.rs`](../src/rules/model.rs)
  - 单条已经规范化、校验过的规则。
- `RuleSet`
  - 文件：[`src/rules/pool/mod.rs`](../src/rules/pool/mod.rs)
  - 持有 `Vec<Rule>` 和编译后的索引。
- `LiveRuleSet`
  - 文件：[`src/rules/pool/mod.rs`](../src/rules/pool/mod.rs)
  - 运行时共享的热更新句柄，底层是 `ArcSwap<RuleSet>`。

## 加载路径

```text
config.yml
  -> Vec<RuleSchema>
  -> RuleSet::try_from(...)
  -> Vec<Rule>
  -> CompiledRuleIndex::compile(&entries)
  -> RuleSet { entries, index }
  -> LiveRuleSet
```

相关文件：

- [`src/rules/compile.rs`](../src/rules/compile.rs)
- [`src/rules/pool/compiled.rs`](../src/rules/pool/compiled.rs)

## 运行时匹配路径

```text
请求 URL
  -> LiveRuleSet::snapshot()
  -> RuleSet::resolve(url)
  -> LookupContext::from_url(url)
  -> CompiledRuleIndex::resolve(...)
  -> 候选规则索引
  -> Rule::resolve_with_lookup(...)
  -> MatchedRule
```

`MatchedRule` 包含：

- 命中的原始 `Rule`
- 这次请求对应的解析后动作

相关文件：

- [`src/rules/pool/runtime.rs`](../src/rules/pool/runtime.rs)
- [`src/rules/matching.rs`](../src/rules/matching.rs)

## DNS 匹配路径

Fake DNS 只关心一个问题：

```text
这个 host 要不要进入 fake-ip 流程？
```

对应路径是：

```text
host
  -> LiveRuleSet::matches_dns_host(host)
  -> RuleSet::matches_dns_host(host)
  -> CompiledRuleIndex::matches_dns_host(host)
```

调用方：

- [`src/traffic/shared/dns/mod.rs`](../src/traffic/shared/dns/mod.rs)

## 编译后索引

`CompiledRuleIndex` 当前包含：

- 精确 URL map
- 同 origin 的 prefix trie
- 精确 host map
- host suffix trie
- 精确 IP map
- IPv4 CIDR trie
- IPv6 CIDR trie
- DNS 精确 host 集合

实现文件：

- [`src/rules/pool/compiled.rs`](../src/rules/pool/compiled.rs)
- [`src/rules/pool/trie.rs`](../src/rules/pool/trie.rs)

## 当前优化点

- 请求相关 key 先在 `LookupContext` 里预计算一次。
- `LiveRuleSet` 使用 `ArcSwap`，读取规则不需要拿锁。
- 精确匹配桶使用 boxed slice，而不是可增长 `Vec`。
- host 后缀匹配和 DNS 后缀匹配共用一棵 trie。
- prefix、host suffix、CIDR trie 都保存 `min_rule_index`，可以提前剪枝。
- 规则顺序仍然有效，配置里越靠前优先级越高。

## 当前规则语义

支持的 matcher：

- `exact`
- `prefix`
- `host`
- `hosts`
- `host_suffix`
- `ip`
- `ip_cidr`

支持的 action：

- `mirror`
- `direct`
- `reject`

说明：

- `ip` 和 `ip_cidr` 只匹配 URL host 本身就是字面量 IP 的请求。
- 规则匹配阶段不会先把域名解析成真实 IP 再匹配。
