# AnyMirror

AnyMirror is a transparent L3 proxy and URL redirection tool written in Rust. It intercepts outbound network traffic at the IP layer and redirects requests to specified mirror destinations without requiring client-side configuration.

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

- Rust toolchain 1.70+
- Explicit mode:
  - No WinDivert dependency
  - Works as a normal local HTTP/HTTPS proxy
- Transparent mode:
  - Windows 10 or later
  - Administrator privileges
  - WinDivert driver files available beside the executable

## Installation & Setup

### 1. Install WinDivert Driver

The transparent proxy mode requires the WinDivert driver. Download and install it:

1. Download WinDivert from the [official releases page](https://reqrypt.org/windivert.html)
2. Extract the archive. You need the following files in your project directory:
   - `WinDivert64.sys` (or `WinDivert32.sys` for 32-bit systems) - the kernel driver
   - `WinDivert.dll` - the runtime library
   - `WinDivert.lib` - the import library (needed for compilation)
3. The driver will be loaded automatically when you run anymirror in transparent mode with administrator privileges

**Note:** Place all three files in the project root directory where the executable will run.

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

`--watch-config` currently hot reloads only the rule set (`includes` / `rules`). Changes to
listener ports or backend settings still require a full process restart.

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
- **backend.dns.listen**: Local fake-ip DNS server address. Transparent fake-ip mode expects your system or application DNS to query this address.
- **backend.dns.fake_ipv4_range**: IPv4 fake-ip pool used for transparent redirection. WinDivert only intercepts TCP connections whose destination falls inside this range.
- **backend.dns.fake_ipv6_range**: IPv6 fake-ip pool used for transparent redirection. WinDivert also intercepts TCP connections whose destination falls inside this range.
- **backend.dns.record_ttl_secs**: TTL used for generated fake A and AAAA records.
- **backend.windivert.layer**: WinDivert capture layer used in transparent mode. Use `network` for local traffic and `network-forward` for forwarded traffic such as WSL, VMs, or gateway scenarios.
- **includes:** List of structured `match + action` rules (see Rule Matching Modes below)

### Config Watch And Hot Reload

When started with `--watch-config`, AnyMirror polls the resolved config file and hot reloads the
rule set in place. The watcher also debounces reloads by waiting until the file modification time
has stayed stable for a short window before reloading.

- Hot reloaded immediately:
  - `includes`
  - `rules`
- Still requires restart:
  - `listen`
  - `tls_port`
  - `backend.dns.*`
  - `backend.windivert.*`

Transparent mode reuses the reloaded rules in both the local proxy and `FakeDnsServer`, so rule
changes affect request matching and fake-ip DNS decisions without restarting the process.

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
```

Structured matcher fields:

- `match.exact`: Match one exact URL
- `match.prefix`: Match one URL prefix
- `match.host`: Match one host
- `match.hosts`: Match any host in a list
- `match.host_suffix`: Match a host suffix such as `example.com`
- `match.scheme`: Optional `http` or `https` restriction for host-based rules
- `match.port`: Optional port restriction for host-based rules
- `match.path_prefix`: Optional path-prefix restriction for host-based rules

Structured actions:

- `action.type: mirror`: Rewrite and forward to the configured upstream
- `action.type: direct`: Keep the original destination and forward directly
- `action.type: reject`: Return a local reject response without contacting the upstream

## Architecture

### Transparent Pipeline

```text
                      +----------------------+
                      |      AppConfig       |
                      | rules / dns / ports  |
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
             +---------+----+    +------+------------------+
             | FakeDnsServer |    |   Intercept Backend    |
             | shared/dns    |    |   current: WinDivert   |
             +---------+----+    +------+------------------+
                       |                |
                       |                |
                       |                v
                       |      +---------+------------------+
                       |      |  DNS UDP responder         |
                       |      |  DNS TCP redirect          |
                       |      |  Fake-IP TCP redirect      |
                       |      |  QUIC drop policy          |
                       |      |  Proxy response rewrite    |
                       |      +---------+------------------+
                       |                |
                       |                v
                       |      +---------+------------------+
                       |      |        Shared NAT          |
                       |      |     traffic/shared/nat     |
                       |      +---------+------------------+
                       |                |
                       +----------------+
                                        |
                                        v
                        +---------------+---------------+
                        |     Local Transparent Proxy   |
                        | HTTP :8787 / TLS :8788        |
                        +---------------+---------------+
                                        |
                                        v
                             +----------+----------+
                             |    Rule Resolution  |
                             |  mirror or direct   |
                             +----------+----------+
                                        |
                      +-----------------+-----------------+
                      |                                   |
                      v                                   v
               +------+-------+                    +------+------+
               | Mirror Upstream|                  | Original Up |
               +----------------+                  +-------------+
```

### Responsibilities

- **FakeDnsServer:** Owns fake-ip allocation and DNS answering for configured origin hosts.
- **Intercept Backend:** Owns packet interception. The current backend is WinDivert, but this layer is intended to be replaceable by future TUN/TAP backends.
- **Shared NAT:** Stores `(client_ip, client_port) -> (original_destination_ip, original_destination_port)` mappings so the backend can restore response packets.
- **Local Transparent Proxy:** Reconstructs the original request target from HTTP Host or HTTPS SNI and executes either mirror forwarding or direct passthrough.

### Request Flow

1. The application resolves a configured host.
2. `FakeDnsServer` returns a fake IPv4 or IPv6 address from the configured fake-ip pools.
3. The intercept backend captures TCP traffic to that fake IP and redirects it to the local proxy listeners.
4. The proxy reconstructs the original URL and evaluates mirror rules.
5. Matched requests go to the configured mirror; unmatched requests go directly to the original upstream.
6. Shared NAT lets the intercept backend rewrite outbound proxy responses back to the original destination tuple.

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
- [x] Structured rule engine with `exact`, `prefix`, `host`, `hosts`, and `host_suffix` matchers
- [x] Structured rule actions with `mirror`, `direct`, and `reject`
- [x] Extensible upstream options (`connect_ip`, `connect_host`, `sni`, and custom upstream DNS)
- [x] CLI startup flow with config alias fallback (`--config mcdev` -> `config.mcdev.yml` etc.)
- [x] Config file watch with rule hot reload via `--watch-config`
- [ ] Full runtime hot reload for listeners, fake DNS server, and intercept backend
- [ ] TUN/TAP device support for cross-platform deployment (macOS, Linux) with user-space TCP/IP stack
- [ ] Encrypted DNS interception for DoH/DoT
- [ ] Advanced rule matching (regex, wildcard host patterns, HTTP version/method filtering)
- [ ] Built-in rule presets/import composition
- [ ] Traffic monitoring and statistics
