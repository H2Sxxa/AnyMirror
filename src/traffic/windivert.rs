#![allow(dead_code)]


use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};

#[cfg(target_os = "windows")]
use windivert::prelude::{WinDivertFlags, WinDivertParam};

fn extract_host(payload: &[u8]) -> Option<String> {
    if payload.len() > 6 {
        for i in 0..payload.len().saturating_sub(6) {
            if payload[i..i+6].eq_ignore_ascii_case(b"Host: ") {
                let start = i + 6;
                let mut end = start;
                while end < payload.len() && payload[end] != b'\r' && payload[end] != b'\n' {
                    end += 1;
                }
                return String::from_utf8(payload[start..end].to_vec()).ok();
            }
        }
    }

    if payload.len() > 43 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01 {
        let mut offset = 43;
        if offset < payload.len() {
            let session_id_len = payload[offset] as usize;
            offset += 1 + session_id_len;
        }
        if offset + 1 < payload.len() {
            let cipher_suites_len = ((payload[offset] as usize) << 8) | (payload[offset+1] as usize);
            offset += 2 + cipher_suites_len;
        }
        if offset < payload.len() {
            let comp_len = payload[offset] as usize;
            offset += 1 + comp_len;
        }
        if offset + 1 < payload.len() {
            let ext_len = ((payload[offset] as usize) << 8) | (payload[offset+1] as usize);
            offset += 2;
            let ext_end = offset + ext_len;
            while offset + 3 < ext_end && offset + 3 < payload.len() {
                let ext_type = ((payload[offset] as u16) << 8) | (payload[offset+1] as u16);
                let ext_data_len = ((payload[offset+2] as usize) << 8) | (payload[offset+3] as usize);
                offset += 4;
                if ext_type == 0x0000 {
                    let mut sni_offset = offset;
                    if sni_offset + 1 < payload.len() {
                        sni_offset += 2;
                        if sni_offset < payload.len() && payload[sni_offset] == 0 {
                            sni_offset += 1;
                            if sni_offset + 1 < payload.len() {
                                let name_len = ((payload[sni_offset] as usize) << 8) | (payload[sni_offset+1] as usize);
                                sni_offset += 2;
                                if sni_offset + name_len <= payload.len() {
                                    return String::from_utf8(payload[sni_offset..sni_offset+name_len].to_vec()).ok();
                                }
                            }
                        }
                    }
                }
                offset += ext_data_len;
            }
        }
    }
    None
}

/// Build- and runtime-facing configuration for a future WinDivert capture backend.
#[derive(Debug, Clone)]
pub struct WinDivertConfig {
    pub local_proxy_addr: SocketAddr,
    pub filter: String,
    pub layer: WinDivertLayer,
    pub priority: i16,
    pub queue_len: u32,
    pub queue_time_ms: u32,
    pub queue_size: u64,
    pub capture_loopback: bool,
    pub sniff: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinDivertLayer {
    Network,
    NetworkForward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinDivertStatus {
    AssetReady,
    UnsupportedPlatform,
}

#[derive(Debug, Clone)]
pub struct WinDivertAssets {
    pub root: PathBuf,
    pub dll_path: PathBuf,
    pub lib_path: PathBuf,
    pub sys_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct WinDivertRuntime {
    config: WinDivertConfig,
    assets: WinDivertAssets,
    backend: RuntimeBackend,
}

#[derive(Debug, Clone)]
enum RuntimeBackend {
    #[cfg(target_os = "windows")]
    Windows(WindowsBackendPlan),
    UnsupportedPlatform,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct WindowsBackendPlan {
    filter: String,
    priority: i16,
    flags: WinDivertFlags,
    queue_len: u32,
    queue_time_ms: u32,
    queue_size: u64,
    layer: WinDivertLayer,
}

impl Default for WinDivertConfig {
    fn default() -> Self {
        let local_proxy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8787);
        Self {
            filter: default_filter(local_proxy_addr, false),
            local_proxy_addr,
            layer: WinDivertLayer::Network,
            priority: 0,
            queue_len: 4096,
            queue_time_ms: 2000,
            queue_size: 4 * 1024 * 1024,
            capture_loopback: false,
            sniff: true,
        }
    }
}

impl WinDivertRuntime {
    pub fn new(config: WinDivertConfig) -> Result<Self> {
        validate_config(&config)?;
        let assets = discover_assets()?;
        let backend = RuntimeBackend::from_config(&config);

        Ok(Self {
            config,
            assets,
            backend,
        })
    }

    pub fn config(&self) -> &WinDivertConfig {
        &self.config
    }

    pub fn assets(&self) -> &WinDivertAssets {
        &self.assets
    }

    pub fn status(&self) -> WinDivertStatus {
        match self.backend {
            RuntimeBackend::UnsupportedPlatform => WinDivertStatus::UnsupportedPlatform,
            #[cfg(target_os = "windows")]
            RuntimeBackend::Windows(_) => WinDivertStatus::AssetReady,
        }
    }

    pub fn plan_summary(&self) -> String {
        match &self.backend {
            RuntimeBackend::UnsupportedPlatform => {
                "windivert backend unavailable on this platform".to_string()
            }
            #[cfg(target_os = "windows")]
            RuntimeBackend::Windows(plan) => format!(
                "layer={:?}, priority={}, filter=\"{}\", queue_len={}, queue_time_ms={}, queue_size={}, sniff={}",
                plan.layer,
                plan.priority,
                plan.filter,
                plan.queue_len,
                plan.queue_time_ms,
                plan.queue_size,
                self.config.sniff
            ),
        }
    }

    #[cfg(target_os = "windows")]
    pub fn start(&self) -> Result<()> {
        use windivert::WinDivert;

        let RuntimeBackend::Windows(plan) = &self.backend else {
            bail!("WinDivert backend plan is missing on Windows");
        };

        let proxy_port = self.config.local_proxy_addr.port();
        let _proxy_ip = match self.config.local_proxy_addr.ip() {
            std::net::IpAddr::V4(v4) => v4.octets(),
            std::net::IpAddr::V6(_) => {
                bail!("IPv6 proxy address is not supported yet");
            }
        };

        match plan.layer {
            WinDivertLayer::Network => {
                let wd = WinDivert::network(&plan.filter, plan.priority, plan.flags)
                    .context("Failed to open WinDivert handle (Network Layer)")?;

                for (param, value) in plan.param_updates() {
                    if let Err(e) = wd.set_param(param, value) {
                        tracing::warn!("Warning: failed to set WinDivert param {:?}: {:?}", param, e);
                    }
                }

                tokio::task::spawn_blocking(move || {
                    let mut rx_buf = vec![0u8; 65535];
                    
                    // (Client_IP, Client_Port) -> (Real_Dest_IP, Real_Dest_Port)
                    let mut nat_table: std::collections::HashMap<(std::net::Ipv4Addr, u16), (std::net::Ipv4Addr, u16)> = std::collections::HashMap::new();

                                        loop {
                        match wd.recv(Some(&mut rx_buf)) {
                            Ok(mut packet) => {
                                let data = packet.data.to_mut();
                                let mut modified = false;

                                if let Ok(ipv4_slice) = etherparse::Ipv4HeaderSlice::from_slice(data) {
                                    let ip_header_len = ipv4_slice.slice().len();
                                    if ipv4_slice.protocol() == etherparse::IpNumber::TCP && data.len() >= ip_header_len + 20 {
                                        let src_ip = std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
                                        let dst_ip = std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);
                                        let src_port = u16::from_be_bytes([data[ip_header_len], data[ip_header_len + 1]]);
                                        let dst_port = u16::from_be_bytes([data[ip_header_len + 2], data[ip_header_len + 3]]);

                                        let mut target_proxy_port = proxy_port;
                                        if dst_port == 443 { target_proxy_port = proxy_port + 1; }

                                        if src_port == proxy_port || src_port == proxy_port + 1 {
                                            if let Some(&(orig_dst_ip, orig_dst_port)) = nat_table.get(&(dst_ip, dst_port)) {
                                                data[12..16].copy_from_slice(&orig_dst_ip.octets());
                                                data[ip_header_len..ip_header_len + 2].copy_from_slice(&orig_dst_port.to_be_bytes());
                                                packet.address.set_outbound(false); // Inject INBOUND so the client socket receives it!
                                                modified = true;
                                            }
                                        } else if dst_port != proxy_port && dst_port != proxy_port + 1 {
                                            nat_table.insert((src_ip, src_port), (dst_ip, dst_port));

                                            // Change DstIP to loopback. 
                                            data[16..20].copy_from_slice(&src_ip.octets());
                                            data[ip_header_len + 2..ip_header_len + 4].copy_from_slice(&target_proxy_port.to_be_bytes());

                                            let mut host_info = String::new();
                                            let mut syn = false;
                                            if let Ok(tcp_slice) = etherparse::TcpHeaderSlice::from_slice(&data[ip_header_len..]) {
                                                syn = tcp_slice.syn();
                                                let tcp_header_len = tcp_slice.slice().len();
                                                if ip_header_len + tcp_header_len < data.len() {
                                                    let payload = &data[ip_header_len + tcp_header_len..];
                                                    if let Some(host) = extract_host(payload) {
                                                        host_info = format!("(Host: {}) ", host);
                                                    }
                                                }
                                            }

                                            packet.address.set_outbound(false); // INBOUND to local stack
                                            modified = true;
                                            if syn || !host_info.is_empty() {
                                                tracing::info!("Intercepted {}->{}:{} {}! Redirecting to {}:{}", src_port, dst_ip, dst_port, host_info, src_ip, target_proxy_port);
                                            }
                                        }
                                    }
                                }

                                if modified {
                                    let _ = packet.recalculate_checksums(
                                        windivert_sys::ChecksumFlags::new()
                                    );
                                }

                                if let Err(e) = wd.send(&packet) {
                                    tracing::error!("WinDivert send failed: {:?}", e);
                                }
                            }
                            Err(e) => {
                                tracing::error!("WinDivert recv failed: {:?}", e);
                                break;
                            }
                        }
                    }
                });
            }
            WinDivertLayer::NetworkForward => {
                let wd = WinDivert::forward(&plan.filter, plan.priority, plan.flags)
                    .context("Failed to open WinDivert handle (Forward Layer)")?;

                for (param, value) in plan.param_updates() {
                    if let Err(e) = wd.set_param(param, value) {
                        tracing::warn!("Warning: failed to set WinDivert param {:?}: {:?}", param, e);
                    }
                }

                tokio::task::spawn_blocking(move || {
                    let mut rx_buf = vec![0u8; 65535];
                    
                    let mut nat_table: std::collections::HashMap<(std::net::Ipv4Addr, u16), (std::net::Ipv4Addr, u16)> = std::collections::HashMap::new();

                                        loop {
                        match wd.recv(Some(&mut rx_buf)) {
                            Ok(mut packet) => {
                                let data = packet.data.to_mut();
                                let mut modified = false;

                                if let Ok(ipv4_slice) = etherparse::Ipv4HeaderSlice::from_slice(data) {
                                    let ip_header_len = ipv4_slice.slice().len();
                                    if ipv4_slice.protocol() == etherparse::IpNumber::TCP && data.len() >= ip_header_len + 20 {
                                        let src_ip = std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
                                        let dst_ip = std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);
                                        let src_port = u16::from_be_bytes([data[ip_header_len], data[ip_header_len + 1]]);
                                        let dst_port = u16::from_be_bytes([data[ip_header_len + 2], data[ip_header_len + 3]]);

                                        let mut target_proxy_port = proxy_port;
                                        if dst_port == 443 { target_proxy_port = proxy_port + 1; }

                                        if src_port == proxy_port || src_port == proxy_port + 1 {
                                            if let Some(&(orig_dst_ip, orig_dst_port)) = nat_table.get(&(dst_ip, dst_port)) {
                                                data[12..16].copy_from_slice(&orig_dst_ip.octets());
                                                data[ip_header_len..ip_header_len + 2].copy_from_slice(&orig_dst_port.to_be_bytes());
                                                packet.address.set_outbound(false); // Inject INBOUND so the client socket receives it!
                                                modified = true;
                                            }
                                        } else if dst_port != proxy_port && dst_port != proxy_port + 1 {
                                            nat_table.insert((src_ip, src_port), (dst_ip, dst_port));

                                            // Change DstIP to loopback. 
                                            data[16..20].copy_from_slice(&src_ip.octets());
                                            data[ip_header_len + 2..ip_header_len + 4].copy_from_slice(&target_proxy_port.to_be_bytes());

                                            let mut host_info = String::new();
                                            let mut syn = false;
                                            if let Ok(tcp_slice) = etherparse::TcpHeaderSlice::from_slice(&data[ip_header_len..]) {
                                                syn = tcp_slice.syn();
                                                let tcp_header_len = tcp_slice.slice().len();
                                                if ip_header_len + tcp_header_len < data.len() {
                                                    let payload = &data[ip_header_len + tcp_header_len..];
                                                    if let Some(host) = extract_host(payload) {
                                                        host_info = format!("(Host: {}) ", host);
                                                    }
                                                }
                                            }

                                            packet.address.set_outbound(false); // INBOUND to local stack
                                            modified = true;
                                            if syn || !host_info.is_empty() {
                                                tracing::info!("Intercepted {}->{}:{} {}! Redirecting to {}:{}", src_port, dst_ip, dst_port, host_info, src_ip, target_proxy_port);
                                            }
                                        }
                                    }
                                }

                                if modified {
                                    let _ = packet.recalculate_checksums(
                                        windivert_sys::ChecksumFlags::new()
                                    );
                                }

                                if let Err(e) = wd.send(&packet) {
                                    tracing::error!("WinDivert send failed: {:?}", e);
                                }
                            }
                            Err(e) => {
                                tracing::error!("WinDivert recv failed: {:?}", e);
                                break;
                            }
                        }
                    }
                });
            }
        }

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn start(&self) -> Result<()> {
        bail!("WinDivert backend is not supported on this platform.");
    }
}

pub fn default_filter(local_proxy_addr: SocketAddr, capture_loopback: bool) -> String {
    let loopback_clause = if capture_loopback {
        ""
    } else {
        " and !loopback"
    };

    // To intercept outbound traffic but allow the proxy's own replies to be intercepted,
    // we must conditionally capture tcp.SrcPort == proxy_port even on loopback.
    format!(
        "outbound and ip and tcp and ( (tcp.DstPort != {} and tcp.DstPort != {}{}) or tcp.SrcPort == {} or tcp.SrcPort == {} )",
        local_proxy_addr.port(),
        local_proxy_addr.port() + 1,
        loopback_clause,
        local_proxy_addr.port(),
        local_proxy_addr.port() + 1
    )
}

fn validate_config(config: &WinDivertConfig) -> Result<()> {
    ensure!(
        !config.filter.trim().is_empty(),
        "windivert filter must not be empty"
    );
    ensure!(
        !config.filter.contains('\n'),
        "windivert filter must be a single line"
    );
    ensure!(
        !config.local_proxy_addr.ip().is_unspecified(),
        "local proxy address must not be unspecified"
    );
    ensure!(
        config.queue_len > 0,
        "windivert queue_len must be greater than zero"
    );
    ensure!(
        config.queue_time_ms > 0,
        "windivert queue_time_ms must be greater than zero"
    );
    ensure!(
        config.queue_size > 0,
        "windivert queue_size must be greater than zero"
    );

    Ok(())
}

fn discover_assets() -> Result<WinDivertAssets> {
    let root = env::var_os("WINDIVERT_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let root = root
        .canonicalize()
        .with_context(|| format!("failed to resolve WINDIVERT_PATH at {}", root.display()))?;

    Ok(WinDivertAssets {
        dll_path: require_file(&root, "WinDivert.dll")?,
        lib_path: require_file(&root, "WinDivert.lib")?,
        sys_path: require_first_existing(&root, &["WinDivert64.sys", "WinDivert32.sys"])?,
        root,
    })
}

fn require_file(root: &Path, file_name: &str) -> Result<PathBuf> {
    let candidate = root.join(file_name);
    ensure!(
        candidate.is_file(),
        "required WinDivert asset is missing: {}",
        candidate.display()
    );
    Ok(candidate)
}

fn require_first_existing(root: &Path, file_names: &[&str]) -> Result<PathBuf> {
    for file_name in file_names {
        let candidate = root.join(file_name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    bail!(
        "required WinDivert driver asset is missing under {} (expected one of: {})",
        root.display(),
        file_names.join(", ")
    )
}

impl RuntimeBackend {
    fn from_config(config: &WinDivertConfig) -> Self {
        #[cfg(target_os = "windows")]
        {
            return Self::Windows(WindowsBackendPlan::from_config(config));
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = config;
            Self::UnsupportedPlatform
        }
    }
}

#[cfg(target_os = "windows")]
impl WindowsBackendPlan {
    fn from_config(config: &WinDivertConfig) -> Self {
        Self {
            filter: config.filter.clone(),
            priority: config.priority,
            flags: build_flags(config),
            queue_len: config.queue_len,
            queue_time_ms: config.queue_time_ms,
            queue_size: config.queue_size,
            layer: config.layer,
        }
    }

    fn param_updates(&self) -> [(WinDivertParam, u64); 3] {
        [
            (WinDivertParam::QueueLength, self.queue_len as u64),
            (WinDivertParam::QueueTime, self.queue_time_ms as u64),
            (WinDivertParam::QueueSize, self.queue_size),
        ]
    }
}

#[cfg(target_os = "windows")]
fn build_flags(config: &WinDivertConfig) -> WinDivertFlags {
    let mut flags = WinDivertFlags::new();
    if config.sniff {
        flags = flags.set_sniff();
    }
    flags
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{WinDivertConfig, default_filter};

    #[test]
    fn default_filter_excludes_proxy_port() {
        let filter = default_filter(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8787),
            false,
        );

        assert!(filter.contains("tcp.DstPort != 8787"));
        assert!(filter.contains("!loopback"));
    }

    #[test]
    fn default_config_is_valid() {
        let config = WinDivertConfig::default();

        assert_eq!(config.local_proxy_addr.port(), 8787);
        assert_eq!(config.queue_size, 4 * 1024 * 1024);
        assert!(!config.filter.is_empty());
    }
}




















