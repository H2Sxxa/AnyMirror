# AnyMirror

[![Codacy Badge](https://app.codacy.com/project/badge/Grade/39c473845ade4c4c9e9e130eee3b3406)](https://app.codacy.com/gh/H2Sxxa/AnyMirror/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/H2Sxxa/AnyMirror)

AnyMirror is a high-performance traffic orchestration gateway written in Rust. It operates as a transparent L3 proxy that intercepts outbound network traffic at the IP layer and routes matched requests through mirror, direct, reject, or plugin-driven policies. In common DNS setups this works without per-application proxy configuration.

## Overview

AnyMirror operates as a transparent fake-ip pipeline:

1. **Allocating fake IPs:** `FakeDnsServer` returns fake A/AAAA records for configured origin hosts.
2. **Intercepting fake-ip traffic:** `backend.kind: windivert` captures outbound DNS plus fake-ip TCP traffic directly; `backend.kind: tun` + `backend.tun.stack: smoltcp` routes fake-ip traffic through a TUN device and accepts TCP/UDP in user space.
3. **Redirecting requests:** WinDivert rewrites captured flows to the local transparent proxy listeners while a shared NAT table keeps the original destination mapping; the smoltcp backend bridges accepted TCP streams into the existing local HTTP/TLS listeners and handles DNS in-tunnel.
4. **Resolving mirror rules:** The local proxy reconstructs the original URL from HTTP Host or HTTPS SNI and decides whether to forward to a mirror or pass through to the original upstream.
5. **Returning responses:** WinDivert rewrites proxy responses back to the original destination tuple before the client receives them; the smoltcp backend returns traffic through the user-space stack and TUN device.

This approach stays transparent to applications while avoiding the classic "same real IP, different host" problem that appears in IP-only interception designs.

## Typical Use Cases

- Accelerate public downloads and dependency fetching by redirecting selected upstreams to mirrors or CDN endpoints
- Run a local explicit HTTP/HTTPS proxy with rule-driven `mirror`, `direct`, `respond`, `reject`, and plugin actions
- Apply transparent fake-ip interception on supported platforms without configuring each application individually
- Return local mock or stub responses for selected endpoints with `respond`, including file-backed payloads
- Explain rule conflicts and request routing decisions through `/rules/explain`
- Practical examples include Minecraft asset mirroring, Maven/Forge dependency acceleration, and local API debugging workflows

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
    - WinDivert runtime files available beside the executable; the official Windows release package already bundles `WinDivert.dll` and `WinDivert64.sys`
  - `backend.kind: tun` + `backend.tun.stack: smoltcp`
    - A desktop OS with TUN support
    - Windows requires `wintun.dll` beside the executable
    - Windows currently auto-configures the TUN adapter DNS; other platforms still require platform-specific DNS setup

## Installation & Setup

### 1. Download A Release Build

For normal usage, start from the latest GitHub release instead of building from source:

- Download the latest package from [GitHub Releases](https://github.com/H2Sxxa/AnyMirror/releases/latest)
- Linux and macOS packages include the `anymirror` binary, `README`, `README.zh`, `LICENSE`, and `config.example.yml`
- The Windows package also includes `WinDivert.dll` and `WinDivert64.sys` for the WinDivert transparent backend
- If you plan to use the TUN backend on Windows, you still need to provide `wintun.dll` separately

### 2. Install WinDivert Driver

The transparent proxy mode requires the WinDivert driver. Download and install it:

1. Download WinDivert from the [official releases page](https://reqrypt.org/windivert.html)
2. Extract the archive.
   - Runtime files: `WinDivert64.sys` (or `WinDivert32.sys`) and `WinDivert.dll`
   - Build-time file: `WinDivert.lib` if you compile AnyMirror from source
3. The driver will be loaded automatically when you run anymirror in transparent mode with administrator privileges

**Note:** Keep the runtime files beside the executable. If you build from source, keep `WinDivert.lib` available for linking as well.

**Note:** You can skip this step when using the official Windows release package unless you want to replace the bundled WinDivert runtime files yourself.

### 3. Install Wintun For The TUN Backend

If you run transparent mode with `backend.kind: tun` on Windows, download `wintun.dll` from the
[official Wintun site](https://wintun.net/) and place it beside the executable.

**Note:** This requirement applies to the TUN backend on Windows. The WinDivert backend does not
use `wintun.dll`.

### 4. Trust the TLS Certificate

When AnyMirror intercepts HTTPS traffic, it re-encrypts that traffic with a self-signed
certificate authority. This applies to transparent HTTPS interception and to explicit-mode HTTPS
proxy requests that are intercepted after `CONNECT`. To avoid security warnings:

1. Run anymirror for the first time - it will generate `anymirror_ca.crt` and `anymirror_ca.key` in the working directory
2. Install the certificate in your system/application:
   - **Windows system trust:** Use `certmgr.msc` or PowerShell to import `anymirror_ca.crt` into the Trusted Root Certification Authorities store
   - **Java/Maven:** Import to the JVM keystore with: `keytool -import -alias anymirror -file anymirror_ca.crt -keystore %JAVA_HOME%\lib\security\cacerts`
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

In explicit mode, configure both the client's HTTP proxy and HTTPS proxy as `127.0.0.1:8787`.
HTTPS proxy traffic also enters through `listen`, then switches to `CONNECT` interception on the
same socket. There is no separate explicit-mode HTTPS proxy port.

`--config` also supports simple aliases. For example, `--config mcdev` will try
`config.mcdev.yaml`, `config.mcdev.yml`, `mcdev.yaml`, and `mcdev.yml` in the current directory.

`--watch-config` hot reloads the config file at runtime. Rule changes are applied in place, and
affected runtime components are restarted inside the same process. This keeps the process alive,
but reload is still not zero-downtime. For detailed reload behavior, see [docs/runtime-reload.md](docs/runtime-reload.md).

### Mode Support

The current runtime supports these combinations:

| CLI mode | Backend | Platform | Notes |
| --- | --- | --- | --- |
| `explicit` | No intercept backend required | Cross-platform | Runs as a local HTTP proxy; HTTPS proxy traffic also enters through the same `listen` port and is intercepted after `CONNECT` |
| `transparent` | `backend.kind: windivert` | Windows only | Uses fake-ip DNS plus WinDivert interception |
| `transparent` | `backend.kind: tun` + `backend.tun.stack: smoltcp` | Experimental desktop platforms with TUN support | Uses a TUN device plus a userspace smoltcp-based netstack |

Transparent mode currently has two backend tracks:

- `backend.kind: windivert`: the mature Windows backend
- `backend.kind: tun` + `backend.tun.stack: smoltcp`: an experimental userspace netstack backend that bridges accepted TCP streams into the existing local HTTP/TLS listeners and resolves DNS in-tunnel

Inside transparent mode, WinDivert still supports these layers:

- `backend.windivert.layer: network`: intercept traffic originating from the local host
- `backend.windivert.layer: network-forward`: intercept forwarded traffic for gateway-style setups such as WSL, VMs, or LAN clients

## Configuration

Start from `config.example.yml`, then copy it to `config.yml` and adjust it for your environment:

```yaml
listen: 127.0.0.1:8787
# tls_port: 8788  # Optional: customize the transparent HTTPS interception port (default: listen_port + 1)
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
observability:
  enable: false
  telemetry:
    service_name: anymirror
    otlp_endpoint: http://127.0.0.1:4317   # Jaeger / OTel Collector OTLP gRPC endpoint

plugins:
  enabled: false
  workers: 4

includes:
  - match:
      prefix: https://downloads.example.com/packages/
    action:
      type: mirror
      upstream:
        url: https://mirror.example.net/packages/

  - match:
      hosts:
        - api.example.com
        - files.example.com
      scheme: https
    action:
      type: direct

  - match:
      exact: https://api.example.com/health
    action:
      type: respond
      status: 200
      body:
        json:
          ok: true
          source: anymirror

  - match:
      host: telemetry.example.com
    action:
      type: reject
      status: 451
      message: blocked by policy
```

For the full configuration reference, see [docs/configuration.md](docs/configuration.md).

### Rule Matching

AnyMirror uses structured `match + action` rules.

- Matchers: `exact`, `prefix`, `host`, `hosts`, `host_suffix`, `ip`, `ip_cidr`
- Actions: `mirror`, `direct`, `respond`, `plugin`, `reject`
- `priority` accepts `xhigh`, `high`, `medium`, `low`, `xlow`, or a numeric value
- `spread: true` allows the winning rule at one priority level to keep propagating to lower-priority levels
- `respond` supports `body.text`, `body.json`, `body.base64`, and `body.file`

For the full rule reference and internal rule-engine model, see [docs/rule-engine.md](docs/rule-engine.md).

## Debug Endpoints

- `GET /observability/state`: current in-memory runtime snapshot
- `GET /observability/events`: recent in-memory runtime events
- `GET /rules/explain?url=<url>`: explain candidate rule evaluation by `priority`, config order, and `spread`
- `GET /tools/rewrite?url=<url>`: inspect rewritten upstream targets
- `GET /tools/fetch?url=<url>`: forward one URL through the current rule pipeline

In explicit mode, clients should point both HTTP and HTTPS proxy settings at `listen` (for example `127.0.0.1:8787`). `tls_port` is only used by transparent mode.

## Project Status

- The core transparent fake-ip pipeline is implemented and usable today.
- `backend.kind: windivert` is the primary transparent backend today, with `Network` and `NetworkForward` support on Windows.
- `backend.kind: tun` + `backend.tun.stack: smoltcp` is available as an experimental backend.
- Explicit mode now supports HTTP proxying and HTTPS interception after `CONNECT`.
- Structured rules, hot reload, upstream DNS controls, built-in `respond` actions, and the QuickJS plugin runtime are already part of the current runtime.
- The observability subsystem now exposes in-memory runtime snapshots and recent events through `GET /observability/state` and `GET /observability/events`.

## Roadmap

The next practical work is centered on debuggability, runtime visibility, and rule ergonomics.
Transparent-mode-specific hard problems such as client-side DoH/DoT interception are intentionally
kept later.

### Near Term

- In-memory metrics and traffic statistics
- Richer observability HTTP API for metrics, worker status, and expanded runtime/reload state
- Rule groups with shared match scope, behaviors, and tags
- Advanced structured matching (`method`, richer path/query constraints, optional wildcard host rules)
- Built-in rule presets/import composition
- Plugin file watch and automatic plugin-only reload triggers
- Rule behaviors for latency simulation and richer `respond` templating
- Official OpenAPI / Swagger-driven plugin workflows for API development

### Mid Term

- Web UI for traffic dashboard, rule debugging, and runtime inspection
- System proxy management for explicit mode
- Plugin event emission and delivery hooks

### Longer Term

- Production-ready cross-platform TUN/TAP support, including the `system` stack and platform-native hosts
- Encrypted DNS interception for client-side DoH/DoT in transparent mode
