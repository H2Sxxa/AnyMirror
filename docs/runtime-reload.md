# Runtime Reload

This document explains how `--watch-config` works and what is reloaded when the config changes.

## Overview

When started with `--watch-config`, AnyMirror:

1. polls the resolved config file path
2. waits for the file modification time to stay stable for a short debounce window
3. reloads the config
4. applies either in-place rule replacement or component restarts

The process stays alive, but runtime reload is not zero-downtime.

## Immediate Rule Reload

These changes are applied in place without restarting runtime components:

- `includes`
- `rules`

The new `RuleSet` is compiled and atomically swapped into `LiveRuleSet`.

## Component Restarts

The current reload plan is component-scoped:

- `listen`
  - explicit mode: restart the HTTP listener
  - transparent mode: restart the HTTP listener and the intercept backend
- `tls_port`
  - restart the TLS listener and the intercept backend
- `backend.dns.listen`
  - restart the fake DNS state/runtime and the intercept backend
- `backend.dns.fake_ipv4_range`
  - restart the fake DNS state/runtime and the intercept backend
- `backend.dns.fake_ipv6_range`
  - restart the fake DNS state/runtime and the intercept backend
- `backend.dns.record_ttl_secs`
  - restart the fake DNS state/runtime and the intercept backend
- `backend.kind`
  - restart only the intercept backend
- `backend.windivert.*`
  - restart only the intercept backend
- `backend.tun.*`
  - restart only the intercept backend

## Runtime Model

The current runtime uses:

- supervisors for long-lived components
- workers for background tasks
- in-process sequential restart for affected components

This means:

- unchanged components are kept alive
- affected components are shut down and started again inside the same process
- queued runtime reload requests are coalesced by generation, so only the newest pending generation is applied

## Current Limits

- Reload is generation-sequenced, but not generation-overlapped.
- There can be a short interruption while a component is restarted.
- Existing transparent connections can be reset when the fake DNS state/runtime or intercept backend is reloaded.
- Client-side DoH/DoT interception is still not supported.

## Related Files

- [`src/watch.rs`](../src/watch.rs)
- [`src/gateway/runtime.rs`](../src/gateway/runtime.rs)
- [`src/supervisors`](../src/supervisors)
