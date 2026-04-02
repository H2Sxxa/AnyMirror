# AnyMirror

AnyMirror is a transparent L3 proxy and URL redirection tool written in Rust. It intercepts outbound network traffic at the IP layer and redirects requests to specified mirror destinations without requiring client-side configuration.

## Overview

AnyMirror operates at Layer 3 (Network Layer) by:

1. **Intercepting packets:** Using WinDivert driver to capture all outbound TCP traffic matching filter rules.
2. **Extracting host information:** Parsing SNI from TLS ClientHello for HTTPS requests and extracting Host header from HTTP requests.
3. **Performing NAT redirection:** Modifying destination IP and port in captured packets, then injecting them back into the local network stack as if they originated from the proxy service running on localhost.
4. **Handling responses:** Maintaining a NAT translation table to reverse-map incoming responses and restore original destination information.

This approach works transparently to applications - no client configuration, proxy settings, or environment variables are needed.

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

```bash
# Display help
cargo run -- --help

# Explicit proxy mode (standard HTTP/HTTPS proxy on port 8787)
cargo run -- --mode explicit --config config.yml

# Transparent mode (intercepts outbound traffic locally)
cargo run -- --mode transparent --config config.yml

# Transparent gateway mode (intercepts forwarded traffic from LAN/WSL/virtual machines)
cargo run -- --mode transparent --layer network-forward --config config.yml
```

## Configuration

Create a `config.yml` file with your redirection rules:

```yaml
listen: 127.0.0.1:8787
# tls_port: 8788  # Optional: customize HTTPS proxy port (default: listen_port + 1)
windivert:
  hot_reload: false # Optional: keep request filters targeted and hot-swap request generations as DNS target IPs change

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
- **windivert.hot_reload** (optional): Enables targeted WinDivert request filters backed by a DNS-driven target store. When the active target IP set changes, anymirror hot-swaps the request capture generation after a grace period instead of widening one long-lived handle forever.
- **includes:** List of URL redirection rules (see Rule Matching Modes below)

### Rule Matching Modes

- **prefix:** Matches any request where the URL path starts with the "origin" path. Useful for redirecting entire directory trees. Query strings are preserved.
- **exact:** Matches only requests with the exact URL (scheme, host, port, path, and query must all match). Default mode for URLs not ending with `/`.

If the `kind` field is omitted, it defaults to `prefix` for URLs ending with `/` and `exact` otherwise. The proxy handles both HTTP and HTTPS traffic transparently, extracting the original hostname and rewriting requests accordingly.

## Architecture

### L3 Proxy Implementation

The transparent proxy intercepts packets at the IP layer using WinDivert:

- **Outbound redirection:** When your application makes a request to blocked.example.com on port 443, WinDivert captures the packet before it leaves the host. The proxy modifies the destination IP to 127.0.0.1 and port to 8788, then injects it back into the network stack. The local proxy service receives the connection on that port.

- **Inbound response handling:** When the proxy responds, WinDivert recognizes it as a response from the proxy service and reverses the NAT translation, restoring the original destination information before the packet goes to the client application.

- **Connection isolation:** A NAT translation table maintains mappings between (client_ip, client_port) and (original_destination_ip, original_destination_port) to ensure responses are correctly routed.

### Host Resolution

- **HTTP requests:** The proxy extracts the Host header to determine the original destination.
- **HTTPS requests:** The proxy extracts SNI (Server Name Indication) from the TLS ClientHello handshake packet before the encrypted connection is established.

Both extraction methods work at the packet level without requiring TLS decryption at the initial interception stage.

## Technical Details

- **IPv4 & IPv6 Dual-Stack Support:**
  Transparent proxy mode captures both IPv4 and IPv6 traffic automatically, ensuring complete coverage in modern hybrid network environments.

- **Full HTTP Capabilities:**
  Seamless streaming of all HTTP methods (GET, POST, PUT, DELETE, etc.) including high-performance bidirectional request and response body forwarding powered by Hyper.

- **WinDivert modes:**
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
