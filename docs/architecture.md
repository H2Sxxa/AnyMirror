# Architecture

This document explains the current transparent-mode architecture of AnyMirror.

## Transparent Pipeline

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
| HTTP/TLS     |  | shared/dns    |            | current: WinDivert|
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
                      |    upstream choice   |
                      +----------+-----------+
                                 |
                   +-------------+-------------+
                   |                           |
                   v                           v
            +------+-------+            +------+------+ 
            | Mirror Upstream|          | Original Up |
            +----------------+          +-------------+
```

## Responsibilities

- `FakeDnsServer`
  - Allocates fake IPv4 and IPv6 addresses for configured hosts.
  - Answers fake DNS requests and consults the live rule set for fake-ip eligibility.
- `Intercept Backend`
  - Owns packet interception.
  - The current implementation is WinDivert.
  - This layer is intended to stay replaceable by future TUN/TAP backends.
- `Shared NAT`
  - Stores `(client_ip, client_port) -> (original_destination_ip, original_destination_port)` mappings.
  - Lets the intercept backend rewrite outbound proxy responses back to the original tuple.
- `Local Proxy`
  - Reconstructs the original request target from HTTP Host or HTTPS SNI.
  - Applies the rule engine and executes either mirror forwarding or direct passthrough.
- `LiveRuleSet`
  - Shares the compiled rule engine across the proxy path and the fake DNS path.
  - Supports in-process hot replacement.

## Request Flow

1. The application resolves a host that matches fake-ip DNS policy.
2. `FakeDnsServer` returns a fake IPv4 or IPv6 address from the configured pools.
3. The intercept backend captures TCP traffic to that fake IP and redirects it to the local proxy listeners.
4. The proxy reconstructs the original URL and evaluates the rule set.
5. Matched requests go to the configured mirror; unmatched requests go directly to the original upstream.
6. Shared NAT lets the intercept backend restore response packets back to the original destination tuple.

## Notes

- Transparent mode currently supports only the WinDivert intercept backend.
- QUIC is not proxied. Fake-ip QUIC traffic is dropped to force TCP/TLS fallback.
- The architecture is intentionally `FakeDnsServer + Intercept Backend + Local Proxy`, not a full user-space TCP/IP stack.
