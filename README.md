# AnyMirror

[![Codacy Badge](https://app.codacy.com/project/badge/Grade/39c473845ade4c4c9e9e130eee3b3406)](https://app.codacy.com/gh/H2Sxxa/AnyMirror/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/H2Sxxa/AnyMirror)

AnyMirror is a transparent L3 proxy and URL redirection tool written in Rust. It intercepts outbound network traffic at the IP layer and redirects selected requests to mirror or policy destinations. In common DNS setups this works without per-application proxy configuration.

## Overview

AnyMirror operates as a transparent fake-ip pipeline:

1. **Allocating fake IPs:** `FakeDnsServer` returns fake A/AAAA records for configured origin hosts.
2. **Intercepting fake-ip traffic:** `backend.kind: windivert` captures outbound DNS plus fake-ip TCP traffic directly; `backend.kind: tun` + `backend.tun.stack: smoltcp` routes fake-ip traffic through a TUN device and accepts TCP/UDP in user space.
3. **Redirecting requests:** WinDivert rewrites captured flows to the local transparent proxy listeners while a shared NAT table keeps the original destination mapping; the smoltcp backend bridges accepted TCP streams into the existing local HTTP/TLS listeners and handles DNS in-tunnel.
4. **Resolving mirror rules:** The local proxy reconstructs the original URL from HTTP Host or HTTPS SNI and decides whether to forward to a mirror or pass through to the original upstream.
5. **Returning responses:** WinDivert rewrites proxy responses back to the original destination tuple before the client receives them; the smoltcp backend returns traffic through the user-space stack and TUN device.

This approach stays transparent to applications while avoiding the classic "same real IP, different host" problem that appears in IP-only interception designs.

## Typical Use Cases

- Accelerate Minecraft game server downloads by redirecting official resource servers (libraries.minecraft.net, resources.download.minecraft.net) to CDN mirrors
- Speed up Maven dependency resolution by redirecting maven.minecraftforge.net to BMCLAPI or similar mirrors
- General URL redirection for network optimization in restricted or slow network environments

## Requirements

### Build Requirements

- Rust toolchain 1.70+
- WinDivert SDK files available when building transparent mode from source

### Runtime Requirements

- Explicit mode:
  - No WinDivert dependency
  - Works as a normal local HTTP/HTTPS proxy
- Transparent mode:
  - Administrator/root privileges or equivalent permission to create interception/TUN resources
  - `backend.kind: windivert`
    - Windows 10 or later
    - WinDivert runtime files available beside the executable
  - `backend.kind: tun` + `backend.tun.stack: smoltcp`
    - A desktop OS with TUN support
    - Windows requires `wintun.dll` beside the executable
    - Windows currently auto-configures the TUN adapter DNS; other platforms still require platform-specific DNS setup

## Installation & Setup

### 1. Install WinDivert Driver

The transparent proxy mode requires the WinDivert driver. Download and install it:

1. Download WinDivert from the [official releases page](https://reqrypt.org/windivert.html)
2. Extract the archive.
   - Runtime files: `WinDivert64.sys` (or `WinDivert32.sys`) and `WinDivert.dll`
   - Build-time file: `WinDivert.lib` if you compile AnyMirror from source
3. The driver will be loaded automatically when you run anymirror in transparent mode with administrator privileges

**Note:** Keep the runtime files beside the executable. If you build from source, keep `WinDivert.lib` available for linking as well.

### 2. Install Wintun For The TUN Backend

If you run transparent mode with `backend.kind: tun` on Windows, download `wintun.dll` from the
[official Wintun site](https://wintun.net/) and place it beside the executable.

**Note:** This requirement applies to the TUN backend on Windows. The WinDivert backend does not
use `wintun.dll`.

### 3. Trust the TLS Certificate

When running in transparent mode, anymirror intercepts HTTPS traffic and re-encrypts it with a self-signed certificate. To avoid security warnings:

1. Run anymirror for the first time - it will generate `anymirror.crt` and `anymirror.key` in the working directory
2. Install the certificate in your system/application:
   - **Windows system trust:** Use `certmgr.msc` or PowerShell to import `anymirror.crt` into the Trusted Root Certification Authorities store
   - **Java/Maven:** Import to the JVM keystore with: `keytool -import -alias anymirror -file anymirror.crt -keystore %JAVA_HOME%\lib\security\cacerts`
   - **Browser:** Import the certificate into your browser's trusted CA list

3. After trusting the certificate, HTTPS interception will work without warnings

**Note:** The proxy will work even without trusting the certificate, but applications will display security warnings/errors.

## Usage

The examples below assume the built executable is available on your `PATH` as `anymirror`.

```bash
# Display help
anymirror --help

# Explicit proxy mode (standard HTTP/HTTPS proxy on port 8787)
anymirror --mode explicit --config config.yml

# Transparent mode (intercepts outbound traffic locally)
anymirror --mode transparent --config config.yml

# Watch the config file and hot reload rules/includes on change
anymirror --mode transparent --config config.yml --watch-config

# Transparent gateway mode: set backend.windivert.layer to network-forward in config.yml
anymirror --mode transparent --config config.yml
```

`--config` also supports simple aliases. For example, `--config mcdev` will try
`config.mcdev.yaml`, `config.mcdev.yml`, `mcdev.yaml`, and `mcdev.yml` in the current directory.

`--watch-config` hot reloads the config file at runtime. Rule changes are applied in place, and
affected runtime components are restarted inside the same process. This keeps the process alive,
but reload is still not zero-downtime. For detailed reload behavior, see [docs/runtime-reload.md](docs/runtime-reload.md).

### Mode Support

The current runtime supports these combinations:

| CLI mode | Backend | Platform | Notes |
| --- | --- | --- | --- |
| `explicit` | No intercept backend required | Cross-platform | Runs as a standard local HTTP/HTTPS proxy |
| `transparent` | `backend.kind: windivert` | Windows only | Uses fake-ip DNS plus WinDivert interception |
| `transparent` | `backend.kind: tun` + `backend.tun.stack: smoltcp` | Experimental desktop platforms with TUN support | Uses a TUN device plus a userspace smoltcp-based netstack |

Transparent mode currently has two backend tracks:

- `backend.kind: windivert`: the mature Windows backend
- `backend.kind: tun` + `backend.tun.stack: smoltcp`: an experimental userspace netstack backend that bridges accepted TCP streams into the existing local HTTP/TLS listeners and resolves DNS in-tunnel

Inside transparent mode, WinDivert still supports these layers:

- `backend.windivert.layer: network`: intercept traffic originating from the local host
- `backend.windivert.layer: network-forward`: intercept forwarded traffic for gateway-style setups such as WSL, VMs, or LAN clients

## Configuration

Create a `config.yml` file with your redirection rules:

```yaml
listen: 127.0.0.1:8787
# tls_port: 8788  # Optional: customize HTTPS proxy port (default: listen_port + 1)
backend:
  kind: windivert              # windivert or tun
  dns:
    listen: 127.0.0.1:53        # Used by the local fake DNS listener; tun+smoltcp handles DNS in-tunnel
    fake_ipv4_range: 198.18.0.0/16
    fake_ipv6_range: fd00:198:18::/48
    record_ttl_secs: 60
  windivert:
    layer: network              # network or network-forward
  tun:
    name: anymirror-tun         # TUN device name
    mtu: 1500
    stack: smoltcp              # system or smoltcp (system is currently TODO)
    platform_dns: auto          # auto or manual
    dns_hijack:                 # Optional: DNS hijack targets for tun+smoltcp
      - any:53                 # UDP DNS hijack
      - tcp://any:53           # TCP DNS hijack
telemetry:
  enabled: true
  service_name: anymirror
  otlp_endpoint: http://127.0.0.1:4317   # Jaeger / OTel Collector OTLP gRPC endpoint

includes:
  - match:
      prefix: https://libraries.minecraft.net/
    action:
      type: mirror
      upstream:
        url: https://bmclapi2.bangbang93.com/maven/

  - match:
      host: resources.download.minecraft.net
    action:
      type: mirror
      upstream:
        url: https://bmclapi2.bangbang93.com/assets/

  - match:
      exact: https://maven.minecraftforge.net
    action:
      type: mirror
      upstream:
        url: https://bmclapi2.bangbang93.com/maven

  - match:
      exact: https://example.com/api
    action:
      type: mirror
      upstream:
        url: https://api.backend.local
        connect_ip: 10.0.0.5
        connect_host: api.internal.local
        sni: backend.local
        dns:
          mode: doh
          server: https://dns.google/dns-query
```

### Configuration Fields

- **listen:** Server address and port to bind to (e.g., `127.0.0.1:8787`)
- **tls_port** (optional): Custom HTTPS proxy port. If not specified, defaults to `listen_port + 1`. For example, if `listen` is `127.0.0.1:8787`, the HTTPS port will be `8788` unless overridden here.
- **backend.kind**: Transparent intercept backend selector. If omitted, it defaults to `windivert` on Windows and `tun` on non-Windows platforms. Use `windivert` for the mature Windows backend, or `tun` for the experimental TUN backend.
- **backend.dns.listen**: Local fake-ip DNS server address. This is the local fake DNS listener used by WinDivert and by any setup that still wants a localhost fake DNS service. The `tun + smoltcp` backend currently handles DNS in-tunnel and does not start this local listener runtime.
- **backend.dns.fake_ipv4_range**: IPv4 fake-ip pool used for transparent redirection. WinDivert only intercepts TCP connections whose destination falls inside this range.
- **backend.dns.fake_ipv6_range**: IPv6 fake-ip pool used for transparent redirection. WinDivert also intercepts TCP connections whose destination falls inside this range.
- **backend.dns.record_ttl_secs**: TTL used for generated fake A and AAAA records.
- **backend.windivert.layer**: WinDivert capture layer used in transparent mode. Use `network` for local traffic and `network-forward` for forwarded traffic such as WSL, VMs, or gateway scenarios.
- **backend.tun.name**: TUN device name used by the TUN backend.
- **backend.tun.mtu**: TUN MTU used by the TUN backend.
- **backend.tun.stack**: TUN stack selector. `system` is currently TODO. `smoltcp` enables the experimental userspace TCP/IP stack backend.
- **backend.tun.platform_dns**: Controls platform DNS automation for `tun + smoltcp`. `auto` enables platform-specific DNS setup; `manual` leaves DNS configuration to the user. The default is `auto` on Windows and `manual` on other platforms.
- **backend.tun.dns_hijack**: Optional DNS hijack target list for `tun + smoltcp`. `any:53` hijacks UDP DNS to any destination; `tcp://any:53` hijacks TCP DNS to any destination. Reserved in-tunnel DNS addresses are always hijacked even if this list is empty.
- **includes:** List of structured `match + action` rules (see Rule Matching Modes below)

### Current TUN Notes

- `backend.tun.stack: smoltcp` is still experimental.
- The smoltcp backend bridges accepted TCP streams into the existing local HTTP/TLS listeners and resolves UDP/TCP DNS directly in-tunnel.
- The default `backend.tun.dns_hijack` behavior is equivalent to:
  - `any:53`
  - `tcp://any:53`
- The current address reservation model is:
  - first usable fake IPv4 / IPv6 address: TUN interface address
  - second usable fake IPv4 / IPv6 address: TUN DNS address
  - fake-ip allocation starts from the third usable address
- On Windows, AnyMirror currently configures the TUN adapter DNS automatically to the reserved in-tunnel DNS address.
- On Linux, `backend.tun.platform_dns: auto` currently configures TUN link DNS through `resolvectl`.
- The current Linux automation uses `systemd-resolved` link DNS and routing-domain integration, not `nftables` or `iptables` DNS redirect.
- On macOS, automatic TUN DNS configuration is not implemented in the current CLI runtime; use `manual` or a `NetworkExtension` host.
- On other non-Windows desktop platforms, you currently need to point the TUN interface DNS at the reserved in-tunnel DNS address yourself.
- QUIC is still handled by dropping fake-ip UDP/443 traffic to force TCP/TLS fallback.
- The `system` TUN stack is still TODO.

### Current TUN DNS Setup

- Windows:
  - AnyMirror configures the TUN adapter DNS automatically.
  - The TUN backend on Windows also requires `wintun.dll` beside the executable.
- Linux:
  - Set `backend.tun.platform_dns: auto` to configure link DNS with `resolvectl`.
  - The current Linux automation uses `systemd-resolved` link DNS and routing-domain integration, not `nftables` or `iptables` DNS redirect.
  - `manual` leaves DNS setup to you.
- macOS and other non-Windows desktop platforms:
  - AnyMirror does not yet configure interface DNS automatically in the current CLI runtime.
  - Point the TUN interface DNS at the reserved TUN DNS address:
    - IPv4: the second usable address in `backend.dns.fake_ipv4_range`
    - IPv6: the second usable address in `backend.dns.fake_ipv6_range`
  - Example with the default ranges:
    - TUN interface address: `198.18.0.1`
    - TUN DNS address: `198.18.0.2`
    - fake-ip allocation starts at `198.18.0.3`

### Config Watch And Hot Reload

When started with `--watch-config`, AnyMirror polls the resolved config file, debounces editor
writes using a short stable window, and then applies either in-place rule replacement or
component-scoped runtime restarts. For the full reload plan and current limits, see
[docs/runtime-reload.md](docs/runtime-reload.md).

### DNS Resolver Modes

There are two different DNS layers in AnyMirror:

- `backend.dns.*`: Configures the fake-ip DNS state used by transparent mode. For WinDivert this also backs the local fake DNS listener. For `tun + smoltcp`, DNS is answered in-tunnel instead of through a localhost listener.
- `upstream.dns.*`: Configures how the proxy resolves the upstream host for one specific mirror rule.

Supported `upstream.dns.mode` values:

- `system`: Use the operating system DNS configuration
- `udp`: Use a specific plain DNS server over UDP; `upstream.dns.server` is required
- `dot`: Use a specific DNS-over-TLS server; `upstream.dns.server` is required
- `doh`: Use a specific DNS-over-HTTPS server; `upstream.dns.server` is required

- `upstream.dns.server` examples:
  - `udp`: `1.1.1.1` or `1.1.1.1:53`
  - `dot`: `dns.google`, `dns.google:853`, or `tls://dns.google:853`
  - `doh`: full URL like `https://dns.google/dns-query`, or a host that will be expanded to `https://<host>/dns-query`

Still not supported:

- Encrypted DNS interception for client-side DoH/DoT in transparent mode

### Rule Matching Modes

For the internal rule-engine model, load path, runtime match path, and compiled index layout, see [docs/rule-engine.md](docs/rule-engine.md).

The rule engine only uses structured `match + action` rules:

```yaml
includes:
  - match:
      host: meta.fabricmc.net
    action:
      type: mirror
      upstream:
        url: https://bmclapi2.bangbang93.com/fabric-meta/

  - match:
      host_suffix: neoforged.net
      path_prefix: /releases/
    action:
      type: mirror
      upstream:
        url: https://mirror.example.com/neoforge/

  - match:
      hosts:
        - api.example.com
        - download.example.com
      scheme: https
    action:
      type: direct

  - match:
      host_suffix: telemetry.example.com
    action:
      type: reject
      status: 451
      message: blocked by policy

  - match:
      ip: 203.0.113.10
    action:
      type: direct

  - match:
      ip_cidr: 203.0.113.0/24
      port: 443
    action:
      type: reject
      status: 403
      message: blocked literal IP range
```

Structured matcher fields:

- `match.exact`: Match one exact URL
- `match.prefix`: Match one URL prefix
- `match.host`: Match one host
- `match.hosts`: Match any host in a list
- `match.host_suffix`: Match a host suffix such as `example.com`
- `match.ip`: Match one literal IP host in the request URL
- `match.ip_cidr`: Match a literal IP host in the request URL by CIDR range
- `match.scheme`: Optional `http` or `https` restriction for host-based rules
- `match.port`: Optional port restriction for host- or IP-based rules
- `match.path_prefix`: Optional path-prefix restriction for host- or IP-based rules

Notes:

- `match.ip` and `match.ip_cidr` only match requests whose URL host is already a literal IP such as `https://203.0.113.10/file`.
- They do not resolve domain names to real IPs during rule matching.
- Rule order still matters. When multiple rules match, the earliest rule in the config wins.

Structured actions:

- `action.type: mirror`: Rewrite and forward to the configured upstream
- `action.type: direct`: Keep the original destination and forward directly
- `action.type: reject`: Return a local reject response without contacting the upstream

## Architecture
The current transparent pipeline is:

```text
FakeDnsServer -> Intercept Backend -> Local Proxy -> Mirror/Direct upstream
```

For the full transparent architecture, component responsibilities, and request flow, see
[docs/architecture.md](docs/architecture.md).

For plugin lifecycle, request/response action overrides, and response flow, see
[docs/plugin-flow.md](docs/plugin-flow.md).

## Technical Details

- **IPv4 & IPv6 Dual-Stack Support:**
  Transparent proxy mode captures both IPv4 and IPv6 traffic automatically, ensuring complete coverage in modern hybrid network environments.

- **Full HTTP Capabilities:**
  Seamless streaming of all HTTP methods (GET, POST, PUT, DELETE, etc.) including high-performance bidirectional request and response body forwarding powered by Hyper.

- **WinDivert modes (current intercept backend):**
  - `Network`: Captures traffic originating from or destined to the local host
  - `NetworkForward`: Captures traffic being forwarded through the host (enables gateway functionality for WSL, virtual machines, USB tethering, etc.)

- **Socket implementation:** Async I/O via Tokio with Hyper for HTTP/2 support; Rustls for TLS processing

- **Port allocation:**
  - Port 8787: HTTP proxy listener
  - Port 8788: HTTPS proxy listener (auto-selected for port 443 destinations)

## Roadmap

- [x] WinDivert intercept backend (`Network` and `NetworkForward`) for transparent Windows traffic capture
- [x] Fake-IP DNS pipeline with IPv4 and IPv6 address pools
- [x] DNS UDP response synthesis and DNS-over-TCP redirection to the local fake DNS server
- [x] Shared NAT for transparent request redirection and proxy response restoration
- [x] Transparent HTTP and HTTPS interception with dynamic Rustls certificates
- [x] High-performance Hyper-based upstream execution with full request body forwarding
- [x] Structured rule engine with `exact`, `prefix`, `host`, `hosts`, `host_suffix`, `ip`, and `ip_cidr` matchers
- [x] Structured rule actions with `mirror`, `direct`, and `reject`
- [x] Extensible upstream options (`connect_ip`, `connect_host`, `sni`, and custom upstream DNS)
- [x] CLI startup flow with config alias fallback (`--config mcdev` -> `config.mcdev.yml` etc.)
- [x] Full config watch and runtime hot reload via `--watch-config`
- [x] Experimental `backend.kind: tun` + `backend.tun.stack: smoltcp` backend with in-tunnel DNS handling
- [x] Plugin runtime with `on_load`, `on_compile`, `on_request`, and `on_response` stages
- [x] QuickJS plugin engine with module imports, worker pooling, and typed plugin authoring support
- [x] Plugin request/response orchestration with compiled plugin rules, action overrides, and request/response patching
- [x] Plugin body permissions with explicit `on_request.body` / `on_response.body` opt-in and lightweight no-body paths
- [ ] Encrypted DNS interception for DoH/DoT
- [ ] Rule groups with shared match scope, behaviors, and tags
- [ ] Built-in response actions such as `respond` for static or template-driven mock replies
- [ ] Response actions with built-in delay and latency simulation for mock scenarios
- [ ] OpenAPI / Swagger-backed mock actions for API development workflows
- [ ] Configurable observability core with in-memory metrics, recent events, and runtime state snapshots
- [ ] Internal observability HTTP API for metrics, events, workers, and reload/runtime state
- [ ] Web UI for traffic dashboard, rule debugging, and runtime inspection
- [ ] System proxy management for explicit mode
- [ ] Advanced structured matching (`method`, richer path/query constraints, optional wildcard host rules)
- [ ] Built-in rule presets/import composition
- [ ] Plugin file watch and automatic plugin-only reload triggers
- [ ] Traffic monitoring and statistics
- [ ] Production-ready cross-platform TUN/TAP support, including the `system` stack and platform-native hosts (longer-term)
