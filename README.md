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

- Windows 10 or later (WinDivert-based implementation)
- Administrator privileges (required to load WinDivert driver and capture network traffic)
- Rust toolchain 1.70+

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

# Transparent gateway mode: set backend.windivert.layer to network-forward in config.yml
anymirror --mode transparent --config config.yml
```

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
  # Prefix matching (default for URLs ending with /)
  - origin: https://libraries.minecraft.net/
    upstream: 
      url: https://bmclapi2.bangbang93.com/maven
    
  # Prefix matching (explicit)
  - kind: prefix
    origin: https://resources.download.minecraft.net/
    upstream:
      url: https://bmclapi2.bangbang93.com/assets/
    
  # Exact matching (default for specific URLs)
  - kind: exact
    origin: https://maven.minecraftforge.net
    upstream:
      url: https://bmclapi2.bangbang93.com/maven

  # Advanced upstream overrides (SNI, Custom DNS, IP mapping)
  - kind: exact
    origin: https://example.com/api
    upstream:
      url: https://api.backend.local
      connect_ip: 10.0.0.5     # Force connection to a specific IP
      connect_host: api.internal.local # Force DNS resolution against a specific host
      sni: backend.local       # Override TLS Sni server name
      dns:
        mode: doh              # DNS resolution mode: system, udp, or doh
        server: https://dns.google/dns-query # DoH Server (or standard DNS IP for 'udp')
```

### Configuration Fields

- **listen:** Server address and port to bind to (e.g., `127.0.0.1:8787`)
- **tls_port** (optional): Custom HTTPS proxy port. If not specified, defaults to `listen_port + 1`. For example, if `listen` is `127.0.0.1:8787`, the HTTPS port will be `8788` unless overridden here.
- **backend.dns.listen**: Local fake-ip DNS server address. Transparent fake-ip mode expects your system or application DNS to query this address.
- **backend.dns.fake_ipv4_range**: IPv4 fake-ip pool used for transparent redirection. WinDivert only intercepts TCP connections whose destination falls inside this range.
- **backend.dns.fake_ipv6_range**: IPv6 fake-ip pool used for transparent redirection. WinDivert also intercepts TCP connections whose destination falls inside this range.
- **backend.dns.record_ttl_secs**: TTL used for generated fake A and AAAA records.
- **backend.windivert.layer**: WinDivert capture layer used in transparent mode. Use `network` for local traffic and `network-forward` for forwarded traffic such as WSL, VMs, or gateway scenarios.
- **includes:** List of URL redirection rules (see Rule Matching Modes below)

### Rule Matching Modes

- **prefix:** Matches any request where the URL path starts with the "origin" path. Useful for redirecting entire directory trees. Query strings are preserved.
- **exact:** Matches only requests with the exact URL (scheme, host, port, path, and query must all match). Default mode for URLs not ending with `/`.

If the `kind` field is omitted, it defaults to `prefix` for URLs ending with `/` and `exact` otherwise. The proxy handles both HTTP and HTTPS traffic transparently, extracting the original hostname and rewriting requests accordingly.

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

- [x] WinDivert-based L3 packet interception (Network and NetworkForward layers for IPv4 and IPv6)
- [x] SNI extraction for HTTPS interception
- [x] Host header extraction for HTTP interception
- [x] High-performance Hyper-based execution engine with full Request Body & Methods support
- [x] Async socket handling with Tokio and pure Rustls
- [x] Extensible Upstream Configuration (`connect_ip`, `connect_host`, `sni`, and `DoH` custom DNS)
- [x] Command-line interface with clap
- [ ] Configuration file watch and hot reload (automatic reload on config changes)
- [ ] TUN/TAP device support for cross-platform deployment (macOS, Linux) with user-space TCP/IP stack
- [ ] Advanced rule matching (regex, wildcards, HTTP version/method filtering)
- [ ] Traffic monitoring and statistics
