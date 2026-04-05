# AnyMirror

AnyMirror is a transparent L3 proxy and URL redirection tool written in Rust. It intercepts outbound network traffic at the IP layer and redirects selected requests to mirror or policy destinations. In common DNS setups this works without per-application proxy configuration.

## Overview

AnyMirror operates as a transparent fake-ip pipeline:

1. **Allocating fake IPs:** `FakeDnsServer` returns fake A/AAAA records for configured origin hosts.
2. **Intercepting fake-ip traffic:** The current intercept backend, WinDivert, only captures DNS queries and TCP traffic whose destination falls inside the fake-ip ranges.
3. **Performing NAT redirection:** Captured connections are rewritten to the local transparent proxy listeners while a shared NAT table keeps the original destination mapping.
4. **Resolving mirror rules:** The local proxy reconstructs the original URL from HTTP Host or HTTPS SNI and decides whether to forward to a mirror or pass through to the original upstream.
5. **Restoring responses:** The intercept backend rewrites proxy responses back to the original destination tuple before the client receives them.

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
  - Windows 10 or later
  - Administrator privileges
  - WinDivert runtime files available beside the executable

## Installation & Setup

### 1. Install WinDivert Driver

The transparent proxy mode requires the WinDivert driver. Download and install it:

1. Download WinDivert from the [official releases page](https://reqrypt.org/windivert.html)
2. Extract the archive.
   - Runtime files: `WinDivert64.sys` (or `WinDivert32.sys`) and `WinDivert.dll`
   - Build-time file: `WinDivert.lib` if you compile AnyMirror from source
3. The driver will be loaded automatically when you run anymirror in transparent mode with administrator privileges

**Note:** Keep the runtime files beside the executable. If you build from source, keep `WinDivert.lib` available for linking as well.

### 2. Trust the TLS Certificate

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
but reload is still not zero-downtime. For detailed reload behavior, see [docs/runtime-reload.md](/c:/WorkSpace/rust/anymirror/docs/runtime-reload.md).

### Mode Support

The current runtime supports these combinations:

| CLI mode | Backend | Platform | Notes |
| --- | --- | --- | --- |
| `explicit` | No intercept backend required | Cross-platform | Runs as a standard local HTTP/HTTPS proxy |
| `transparent` | `backend.windivert` | Windows only | Uses fake-ip DNS plus WinDivert interception |

Transparent mode currently uses only the WinDivert intercept backend. Inside transparent mode:

- `backend.windivert.layer: network`: intercept traffic originating from the local host
- `backend.windivert.layer: network-forward`: intercept forwarded traffic for gateway-style setups such as WSL, VMs, or LAN clients

On non-Windows platforms, transparent mode is not available and the process will fail fast with an explicit error.

## Configuration

Create a `config.yml` file with your redirection rules:

```yaml
listen: 127.0.0.1:8787
# tls_port: 8788  # Optional: customize HTTPS proxy port (default: listen_port + 1)
backend:
  dns:
    listen: 127.0.0.1:15353     # Local fake-ip DNS server; 5353 is commonly occupied by mDNS on Windows
    fake_ipv4_range: 198.18.0.0/16
    fake_ipv6_range: fd00:198:18::/48
    record_ttl_secs: 60
  windivert:
    layer: network              # network or network-forward

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
- **backend.dns.listen**: Local fake-ip DNS server address. This is the local fake DNS listener used by transparent mode. Ordinary UDP/53 and TCP/53 traffic can be redirected into it by the intercept backend; pointing system or application DNS directly at it is mainly useful in special DNS environments.
- **backend.dns.fake_ipv4_range**: IPv4 fake-ip pool used for transparent redirection. WinDivert only intercepts TCP connections whose destination falls inside this range.
- **backend.dns.fake_ipv6_range**: IPv6 fake-ip pool used for transparent redirection. WinDivert also intercepts TCP connections whose destination falls inside this range.
- **backend.dns.record_ttl_secs**: TTL used for generated fake A and AAAA records.
- **backend.windivert.layer**: WinDivert capture layer used in transparent mode. Use `network` for local traffic and `network-forward` for forwarded traffic such as WSL, VMs, or gateway scenarios.
- **includes:** List of structured `match + action` rules (see Rule Matching Modes below)

### Config Watch And Hot Reload

When started with `--watch-config`, AnyMirror polls the resolved config file, debounces editor
writes using a short stable window, and then applies either in-place rule replacement or
component-scoped runtime restarts. For the full reload plan and current limits, see
[docs/runtime-reload.md](/c:/WorkSpace/rust/anymirror/docs/runtime-reload.md).

### DNS Resolver Modes

There are two different DNS layers in AnyMirror:

- `backend.dns.*`: Configures the local fake-ip DNS server used by transparent mode. This is not an upstream resolver mode selector.
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

For the internal rule-engine model, load path, runtime match path, and compiled index layout, see [docs/rule-engine.md](/c:/WorkSpace/rust/anymirror/docs/rule-engine.md).

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
[docs/architecture.md](/c:/WorkSpace/rust/anymirror/docs/architecture.md).

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
- [ ] TUN/TAP device support for cross-platform deployment (macOS, Linux) with user-space TCP/IP stack
- [ ] Encrypted DNS interception for DoH/DoT
- [ ] Advanced structured matching (`method`, richer path/query constraints, optional wildcard host rules)
- [ ] Built-in rule presets/import composition
- [ ] Traffic monitoring and statistics
