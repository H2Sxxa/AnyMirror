# Configuration

This document is the reference for `config.yml`.

## Core Fields

- `listen`: Server address and port to bind to, for example `127.0.0.1:8787`.
- `tls_port`:
  Transparent-mode local TLS interception listener. If omitted, it defaults to
  `listen_port + 1`.
- `backend.kind`:
  Transparent intercept backend selector. Defaults to `windivert` on Windows
  and `tun` on non-Windows platforms.
- `includes`:
  Structured `match + action` rule list.
- `observability.enable`:
  Master switch for the observability subsystem.
- `observability.telemetry.service_name`:
  OpenTelemetry service name for exported traces.
- `observability.telemetry.otlp_endpoint`:
  OTLP gRPC endpoint for exported traces.

## Backend DNS

- `backend.dns.listen`:
  Local fake-ip DNS listener address. Used by WinDivert and by setups that
  still want a localhost fake DNS service.
- `backend.dns.fake_ipv4_range`:
  IPv4 fake-ip pool used by transparent redirection.
- `backend.dns.fake_ipv6_range`:
  IPv6 fake-ip pool used by transparent redirection.
- `backend.dns.record_ttl_secs`:
  TTL used for generated fake A and AAAA records.

## WinDivert Backend

- `backend.windivert.layer`:
  WinDivert capture layer used in transparent mode.
  - `network`: local traffic
  - `network-forward`: forwarded traffic such as WSL, VMs, or gateway setups

## TUN Backend

- `backend.tun.name`: TUN device name.
- `backend.tun.mtu`: TUN MTU.
- `backend.tun.stack`:
  TUN stack selector. The current default is `smoltcp`. `system` is still TODO.
- `backend.tun.platform_dns`:
  Platform DNS automation mode for `tun + smoltcp`.
  - Windows default: `auto`
  - Other platforms default: `manual`
- `backend.tun.dns_hijack`:
  Optional DNS hijack target list for `tun + smoltcp`.

Current notes:

- `backend.tun.stack: smoltcp` is still experimental.
- The smoltcp backend bridges accepted TCP streams into the local HTTP/TLS
  listeners and resolves UDP/TCP DNS directly in-tunnel.
- The default DNS hijack behavior is equivalent to:
  - `any:53`
  - `tcp://any:53`
- Client-side encrypted DNS interception for transparent DoH/DoT is still not
  supported.

## Upstream DNS

There are two DNS layers in AnyMirror:

- `backend.dns.*`: fake-ip DNS state for transparent mode
- `upstream.dns.*`: resolver policy for one specific mirror rule

Supported `upstream.dns.mode` values:

- `system`
- `udp`
- `dot`
- `doh`

Examples for `upstream.dns.server`:

- `udp`: `1.1.1.1` or `1.1.1.1:53`
- `dot`: `dns.google`, `dns.google:853`, or `tls://dns.google:853`
- `doh`: full URL such as `https://dns.google/dns-query`

## Watch And Reload

`--watch-config` hot reloads the config file at runtime:

- rule changes are applied in place
- affected runtime components are restarted inside the same process
- reload is not zero-downtime

See [runtime-reload.md](./runtime-reload.md) for the full reload plan and
current limits.
