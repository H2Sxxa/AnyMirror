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
|            gateway::runtime::serve_transparent            |
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
| HTTP/TLS     |  | shared/dns    |            | WinDivert / TUN   |
+----+---------+  +----+---------+            +--------+---------+
     |                 |                               |
     |                 |                               v
     |                 |                    +----------+----------+
     |                 |                    | DNS responder /     |
     |                 |                    | DNS redirect        |
     |                 |                    | Fake-IP TCP redirect|
     |                 |                    | TCP bridge /        |
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
  - The current implementations are WinDivert and the experimental `tun + smoltcp` backend.
  - WinDivert keeps the packet-rewrite path; `tun + smoltcp` accepts TCP/UDP through a user-space stack and bridges accepted TCP streams into the local proxy listeners.
- `Shared NAT`
  - Stores `(client_ip, client_port) -> (original_destination_ip, original_destination_port)` mappings.
  - Lets the WinDivert backend rewrite outbound proxy responses back to the original tuple.
- `Local Proxy`
  - Reconstructs the original request target from HTTP Host or HTTPS SNI.
  - Applies the rule engine and executes either mirror forwarding or direct passthrough.
- `LiveRuleSet`
  - Shares the compiled rule engine across the proxy path and the fake DNS path.
  - Supports in-process hot replacement.

## Request Flow

1. The application resolves a host that matches fake-ip DNS policy.
2. `FakeDnsServer` returns a fake IPv4 or IPv6 address from the configured pools.
3. The intercept backend captures traffic to that fake IP.
   WinDivert rewrites captured TCP packets to the local proxy listeners; `tun + smoltcp` accepts TCP streams in user space and bridges them into the local proxy listeners.
4. The proxy reconstructs the original URL and evaluates the rule set.
5. Matched requests go to the configured mirror; unmatched requests go directly to the original upstream.
6. Shared NAT lets the intercept backend restore response packets back to the original destination tuple.

## Notes

- Transparent mode currently supports the mature WinDivert backend and the experimental `tun + smoltcp` backend.
- QUIC is not proxied. Fake-ip QUIC traffic is dropped to force TCP/TLS fallback.
- WinDivert still uses the packet-rewrite architecture. The `tun + smoltcp` path now resolves DNS in-tunnel and uses an experimental user-space TCP/IP stack.
