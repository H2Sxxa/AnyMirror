use std::{
    collections::HashSet,
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::{bail, ensure, Context, Result};

#[cfg(target_os = "windows")]
use windivert::prelude::WinDivertFlags;

use super::state::{
    new_transparent_nat_table_v4, new_transparent_nat_table_v6, TransparentNatTableV4,
    TransparentNatTableV6, TransparentTargetChangeTx, TransparentTargetStore,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum TransparentCaptureKind {
    TcpRequestRedirect,
    TcpProxyResponse,
    DnsSniffer,
    Generic,
}

impl Default for TransparentCaptureKind {
    fn default() -> Self {
        Self::Generic
    }
}

/// Build- and runtime-facing configuration for a future WinDivert capture backend.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct WinDivertConfig {
    pub local_proxy_addr: SocketAddr,
    pub tls_port: u16,
    pub filter: String,
    pub layer: WinDivertLayer,
    pub priority: i16,
    pub queue_len: u32,
    pub queue_time_ms: u32,
    pub queue_size: u64,
    pub capture_loopback: bool,
    pub sniff: bool,
    pub capture_kind: TransparentCaptureKind,
    pub transparent_hosts: HashSet<String>,
    pub transparent_target_store: TransparentTargetStore,
    pub transparent_nat_table_v4: TransparentNatTableV4,
    pub transparent_nat_table_v6: TransparentNatTableV6,
    pub target_change_tx: Option<TransparentTargetChangeTx>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinDivertLayer {
    Network,
    NetworkForward,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct WinDivertAssets {
    pub root: PathBuf,
    pub dll_path: PathBuf,
    pub lib_path: PathBuf,
    pub sys_path: PathBuf,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct WinDivertRuntime {
    pub config: WinDivertConfig,
    pub assets: WinDivertAssets,
    pub backend: RuntimeBackend,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum RuntimeBackend {
    #[cfg(target_os = "windows")]
    Windows(WindowsBackendPlan),
    UnsupportedPlatform,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub struct WindowsBackendPlan {
    pub filter: String,
    pub priority: i16,
    pub flags: WinDivertFlags,
    pub queue_len: u32,
    pub queue_time_ms: u32,
    pub queue_size: u64,
    pub layer: WinDivertLayer,
}

impl Default for WinDivertConfig {
    fn default() -> Self {
        let local_proxy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8787);
        let tls_port = 8788;
        // Note: filter will be properly set when config is actually used
        let filter = format!(
            "outbound and tcp and ( (tcp.DstPort != {} and tcp.DstPort != {} and !loopback) or tcp.SrcPort == {} or tcp.SrcPort == {} )",
            local_proxy_addr.port(),
            tls_port,
            local_proxy_addr.port(),
            tls_port
        );

        Self {
            filter,
            local_proxy_addr,
            tls_port,
            layer: WinDivertLayer::Network,
            priority: 0,
            queue_len: 4096,
            queue_time_ms: 2000,
            queue_size: 4 * 1024 * 1024,
            capture_loopback: false,
            sniff: true,
            capture_kind: TransparentCaptureKind::Generic,
            transparent_hosts: HashSet::new(),
            transparent_target_store: TransparentTargetStore::from_bootstrap(
                std::iter::empty::<IpAddr>(),
                std::time::Instant::now(),
            ),
            transparent_nat_table_v4: new_transparent_nat_table_v4(),
            transparent_nat_table_v6: new_transparent_nat_table_v6(),
            target_change_tx: None,
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

pub fn discover_assets() -> Result<WinDivertAssets> {
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
    pub fn from_config(config: &WinDivertConfig) -> Self {
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
    pub fn from_config(config: &WinDivertConfig) -> Self {
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

    pub fn param_updates(&self) -> [(windivert::prelude::WinDivertParam, u64); 3] {
        [
            (
                windivert::prelude::WinDivertParam::QueueLength,
                self.queue_len as u64,
            ),
            (
                windivert::prelude::WinDivertParam::QueueTime,
                self.queue_time_ms as u64,
            ),
            (
                windivert::prelude::WinDivertParam::QueueSize,
                self.queue_size,
            ),
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
