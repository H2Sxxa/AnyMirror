# Rule Engine

This document explains how AnyMirror loads, compiles, and matches rules at runtime.

## Layers

```text
RuleSchema
  -> Rule
  -> RuleSet
  -> LiveRuleSet
```

- `RuleSchema`
  - File: [`src/rules/schema.rs`](../src/rules/schema.rs)
  - Human-friendly config shape loaded from YAML.
- `Rule`
  - File: [`src/rules/model.rs`](../src/rules/model.rs)
  - One normalized and validated rule.
- `RuleSet`
  - File: [`src/rules/pool/mod.rs`](../src/rules/pool/mod.rs)
  - Holds `Vec<Rule>` plus the compiled index.
- `LiveRuleSet`
  - File: [`src/rules/pool/mod.rs`](../src/rules/pool/mod.rs)
  - Shared hot-reload handle backed by `ArcSwap<RuleSet>`.

## Load Path

```text
config.yml
  -> Vec<RuleSchema>
  -> RuleSet::try_from(...)
  -> Vec<Rule>
  -> CompiledRuleIndex::compile(&entries)
  -> RuleSet { entries, index }
  -> LiveRuleSet
```

Related files:

- [`src/rules/compile.rs`](../src/rules/compile.rs)
- [`src/rules/pool/compiled.rs`](../src/rules/pool/compiled.rs)

## Runtime Match Path

```text
request URL
  -> LiveRuleSet::snapshot()
  -> RuleSet::resolve(url)
  -> LookupContext::from_url(url)
  -> CompiledRuleIndex::resolve(...)
  -> candidate rule indices
  -> Rule::resolve_with_lookup(...)
  -> MatchedRule
```

`MatchedRule` contains:

- the matched `Rule`
- the resolved action for this request

Related files:

- [`src/rules/pool/runtime.rs`](../src/rules/pool/runtime.rs)
- [`src/rules/matching.rs`](../src/rules/matching.rs)

## DNS Match Path

Fake DNS only needs to answer one question:

```text
should this host enter fake-ip flow?
```

That path is:

```text
host
  -> LiveRuleSet::matches_dns_host(host)
  -> RuleSet::matches_dns_host(host)
  -> CompiledRuleIndex::matches_dns_host(host)
```

Used by:

- [`src/traffic/shared/dns/mod.rs`](../src/traffic/shared/dns/mod.rs)

## Compiled Index

`CompiledRuleIndex` currently stores:

- exact URL map
- same-origin prefix trie
- exact host map
- host suffix trie
- exact IP map
- IPv4 CIDR trie
- IPv6 CIDR trie
- DNS exact host set

Implementation files:

- [`src/rules/pool/compiled.rs`](../src/rules/pool/compiled.rs)
- [`src/rules/pool/trie.rs`](../src/rules/pool/trie.rs)

## Current Optimizations

- Request-derived keys are precomputed once in `LookupContext`.
- `LiveRuleSet` uses `ArcSwap`, so reads do not take a lock.
- Exact match buckets use boxed slices instead of growable vectors.
- Host-suffix matching and DNS suffix matching share one trie.
- Prefix, host-suffix, and CIDR tries keep `min_rule_index` for early pruning.
- Rule order still wins. Earlier config rules have higher priority.

## Current Rule Semantics

Supported matchers:

- `exact`
- `prefix`
- `host`
- `hosts`
- `host_suffix`
- `ip`
- `ip_cidr`

Supported actions:

- `mirror`
- `direct`
- `reject`

Notes:

- `ip` and `ip_cidr` only match requests whose URL host is already a literal IP.
- Rule matching does not resolve a domain to a real IP before matching.
