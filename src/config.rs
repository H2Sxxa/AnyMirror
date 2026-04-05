use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use ipnet::{Ipv4Net, Ipv6Net};
use serde::Deserialize;

use crate::rules::pool::RuleSet;
use crate::rules::schema::RuleSchema;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub listen_addr: SocketAddr,
    pub tls_port: Option<u16>,
    pub backend: BackendOptions,
    pub rules: RuleSet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendOptions {
    pub kind: TransparentBackendKind,
    pub dns: FakeDnsOptions,
    pub windivert: WinDivertBackendOptions,
    pub tun: TunBackendOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparentBackendKind {
    WinDivert,
    Tun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinDivertBackendOptions {
    pub layer: WinDivertLayerConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinDivertLayerConfig {
    Network,
    NetworkForward,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunBackendOptions {
    pub name: String,
    pub mtu: u16,
    pub stack: TunStack,
    pub platform_dns: TunPlatformDnsMode,
    pub dns_hijack: Vec<TunDnsHijackSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunStack {
    System,
    Smoltcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunPlatformDnsMode {
    Auto,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunDnsHijackTransport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunDnsHijackTarget {
    Any(u16),
    Exact(SocketAddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunDnsHijackSpec {
    pub transport: TunDnsHijackTransport,
    pub target: TunDnsHijackTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeDnsOptions {
    pub listen_addr: SocketAddr,
    pub fake_ipv4_range: Ipv4Net,
    pub fake_ipv6_range: Ipv6Net,
    pub record_ttl: Duration,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default = "default_listen_addr")]
    listen: String,
    tls_port: Option<u16>,
    #[serde(default)]
    backend: RawBackendOptions,
    #[serde(default, alias = "rules")]
    includes: Vec<RuleSchema>,
}

#[derive(Debug, Deserialize, Default)]
struct RawBackendOptions {
    #[serde(default = "default_backend_kind")]
    kind: String,
    #[serde(default)]
    dns: RawFakeDnsOptions,
    #[serde(default)]
    windivert: RawWinDivertBackendOptions,
    #[serde(default)]
    tun: RawTunBackendOptions,
}

#[derive(Debug, Deserialize)]
struct RawWinDivertBackendOptions {
    #[serde(default = "default_windivert_layer")]
    layer: String,
}

impl Default for RawWinDivertBackendOptions {
    fn default() -> Self {
        Self {
            layer: default_windivert_layer(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawTunBackendOptions {
    #[serde(default = "default_tun_name")]
    name: String,
    #[serde(default = "default_tun_mtu")]
    mtu: u16,
    #[serde(default = "default_tun_stack")]
    stack: String,
    #[serde(default = "default_tun_platform_dns")]
    platform_dns: String,
    #[serde(default = "default_tun_dns_hijack")]
    dns_hijack: Vec<String>,
}

impl Default for RawTunBackendOptions {
    fn default() -> Self {
        Self {
            name: default_tun_name(),
            mtu: default_tun_mtu(),
            stack: default_tun_stack(),
            platform_dns: default_tun_platform_dns(),
            dns_hijack: default_tun_dns_hijack(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawFakeDnsOptions {
    #[serde(default = "default_backend_dns_listen_addr")]
    listen: String,
    #[serde(default = "default_fake_ipv4_range")]
    fake_ipv4_range: String,
    #[serde(default = "default_fake_ipv6_range")]
    fake_ipv6_range: String,
    #[serde(default = "default_fake_ip_record_ttl_secs")]
    record_ttl_secs: u64,
}

impl Default for RawFakeDnsOptions {
    fn default() -> Self {
        Self {
            listen: default_backend_dns_listen_addr(),
            fake_ipv4_range: default_fake_ipv4_range(),
            fake_ipv6_range: default_fake_ipv6_range(),
            record_ttl_secs: default_fake_ip_record_ttl_secs(),
        }
    }
}

pub fn load_config(path: impl AsRef<Path>) -> Result<AppConfig> {
    let source_path = path.as_ref();
    let raw = fs::read_to_string(source_path)
        .with_context(|| format!("failed to read config file {}", source_path.display()))?;
    let parsed: RawConfig = serde_yaml::from_str(&raw)
        .with_context(|| format!("failed to parse yaml from {}", source_path.display()))?;

    let listen_addr = parsed
        .listen
        .parse()
        .with_context(|| format!("invalid listen address `{}`", parsed.listen))?;
    let rules = RuleSet::try_from(parsed.includes)?;

    if rules.is_empty() {
        bail!("config does not contain any include rules");
    }

    Ok(AppConfig {
        listen_addr,
        tls_port: parsed.tls_port,
        backend: BackendOptions::try_from(parsed.backend)?,
        rules,
    })
}

pub fn resolve_config_path(path: impl AsRef<Path>) -> Result<PathBuf> {
    let input_path = path.as_ref();
    if input_path.is_file() {
        return Ok(input_path.to_path_buf());
    }

    let Some(alias) = extract_config_alias(input_path) else {
        return Ok(input_path.to_path_buf());
    };

    let candidates = [
        format!("config.{alias}.yaml"),
        format!("config.{alias}.yml"),
        format!("{alias}.yaml"),
        format!("{alias}.yml"),
    ];

    for candidate in &candidates {
        let candidate_path = PathBuf::from(candidate);
        if candidate_path.is_file() {
            return Ok(candidate_path);
        }
    }

    bail!(
        "failed to resolve config alias `{}`; tried {}",
        alias,
        candidates.join(", ")
    )
}

fn default_listen_addr() -> String {
    "127.0.0.1:8787".to_string()
}

fn extract_config_alias(path: &Path) -> Option<&str> {
    if path.components().count() != 1 {
        return None;
    }

    let file_name = path.file_name()?.to_str()?;
    if file_name.eq_ignore_ascii_case("config.yml") || file_name.eq_ignore_ascii_case("config.yaml")
    {
        return None;
    }
    if file_name.contains('.') {
        return None;
    }

    Some(file_name)
}

impl TryFrom<RawBackendOptions> for BackendOptions {
    type Error = anyhow::Error;

    fn try_from(value: RawBackendOptions) -> Result<Self> {
        Ok(Self {
            kind: parse_backend_kind(&value.kind)?,
            dns: FakeDnsOptions::try_from(value.dns)?,
            windivert: WinDivertBackendOptions::try_from(value.windivert)?,
            tun: TunBackendOptions::try_from(value.tun)?,
        })
    }
}

impl TryFrom<RawWinDivertBackendOptions> for WinDivertBackendOptions {
    type Error = anyhow::Error;

    fn try_from(value: RawWinDivertBackendOptions) -> Result<Self> {
        Ok(Self {
            layer: parse_windivert_layer(&value.layer)?,
        })
    }
}

impl TryFrom<RawFakeDnsOptions> for FakeDnsOptions {
    type Error = anyhow::Error;

    fn try_from(value: RawFakeDnsOptions) -> Result<Self> {
        let listen_addr = value
            .listen
            .parse()
            .with_context(|| format!("invalid backend.dns.listen `{}`", value.listen))?;
        let fake_ipv4_range = value.fake_ipv4_range.parse::<Ipv4Net>().with_context(|| {
            format!(
                "invalid backend.dns.fake_ipv4_range `{}`",
                value.fake_ipv4_range
            )
        })?;
        let fake_ipv6_range = value.fake_ipv6_range.parse::<Ipv6Net>().with_context(|| {
            format!(
                "invalid backend.dns.fake_ipv6_range `{}`",
                value.fake_ipv6_range
            )
        })?;

        Ok(Self {
            listen_addr,
            fake_ipv4_range,
            fake_ipv6_range,
            record_ttl: Duration::from_secs(value.record_ttl_secs),
        })
    }
}

impl TryFrom<RawTunBackendOptions> for TunBackendOptions {
    type Error = anyhow::Error;

    fn try_from(value: RawTunBackendOptions) -> Result<Self> {
        if value.name.trim().is_empty() {
            bail!("backend.tun.name must not be empty");
        }
        if value.mtu == 0 {
            bail!("backend.tun.mtu must be greater than zero");
        }

        Ok(Self {
            name: value.name,
            mtu: value.mtu,
            stack: parse_tun_stack(&value.stack)?,
            platform_dns: parse_tun_platform_dns(&value.platform_dns)?,
            dns_hijack: value
                .dns_hijack
                .iter()
                .map(|entry| parse_tun_dns_hijack_spec(entry))
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

fn default_backend_dns_listen_addr() -> String {
    "127.0.0.1:15353".to_string()
}

fn default_backend_kind() -> String {
    if cfg!(target_os = "windows") {
        "windivert".to_string()
    } else {
        "tun".to_string()
    }
}

fn default_windivert_layer() -> String {
    "network".to_string()
}

fn default_tun_name() -> String {
    "anymirror-tun".to_string()
}

fn default_tun_mtu() -> u16 {
    1500
}

fn default_tun_stack() -> String {
    "system".to_string()
}

fn default_tun_platform_dns() -> String {
    if cfg!(target_os = "windows") {
        "auto".to_string()
    } else {
        "manual".to_string()
    }
}

fn default_tun_dns_hijack() -> Vec<String> {
    vec!["any:53".to_string(), "tcp://any:53".to_string()]
}

fn default_fake_ipv4_range() -> String {
    "198.18.0.0/16".to_string()
}

fn default_fake_ipv6_range() -> String {
    "fd00:198:18::/48".to_string()
}

fn default_fake_ip_record_ttl_secs() -> u64 {
    60
}

fn parse_windivert_layer(value: &str) -> Result<WinDivertLayerConfig> {
    match value {
        "network" => Ok(WinDivertLayerConfig::Network),
        "network-forward" | "network_forward" => Ok(WinDivertLayerConfig::NetworkForward),
        _ => bail!(
            "invalid backend.windivert.layer `{}` (expected `network` or `network-forward`)",
            value
        ),
    }
}

fn parse_backend_kind(value: &str) -> Result<TransparentBackendKind> {
    match value {
        "windivert" => Ok(TransparentBackendKind::WinDivert),
        "tun" | "tun-rs" | "tun_rs" => Ok(TransparentBackendKind::Tun),
        _ => bail!(
            "invalid backend.kind `{}` (expected `windivert` or `tun`)",
            value
        ),
    }
}

fn parse_tun_stack(value: &str) -> Result<TunStack> {
    match value {
        "system" => Ok(TunStack::System),
        "smoltcp" => Ok(TunStack::Smoltcp),
        _ => bail!(
            "invalid backend.tun.stack `{}` (expected `system` or `smoltcp`)",
            value
        ),
    }
}

fn parse_tun_platform_dns(value: &str) -> Result<TunPlatformDnsMode> {
    match value {
        "auto" => Ok(TunPlatformDnsMode::Auto),
        "manual" => Ok(TunPlatformDnsMode::Manual),
        _ => bail!(
            "invalid backend.tun.platform_dns `{}` (expected `auto` or `manual`)",
            value
        ),
    }
}

fn parse_tun_dns_hijack_spec(value: &str) -> Result<TunDnsHijackSpec> {
    let normalized = value.trim();
    if normalized.is_empty() {
        bail!("invalid backend.tun.dns_hijack entry: value must not be empty");
    }

    let (transport, target) = if let Some(rest) = normalized.strip_prefix("tcp://") {
        (TunDnsHijackTransport::Tcp, rest)
    } else if let Some(rest) = normalized.strip_prefix("udp://") {
        (TunDnsHijackTransport::Udp, rest)
    } else {
        (TunDnsHijackTransport::Udp, normalized)
    };

    let target = parse_tun_dns_hijack_target(target)
        .with_context(|| format!("invalid backend.tun.dns_hijack entry `{}`", value))?;

    Ok(TunDnsHijackSpec { transport, target })
}

fn parse_tun_dns_hijack_target(value: &str) -> Result<TunDnsHijackTarget> {
    if let Some(port) = value.strip_prefix("any:") {
        let port = port
            .parse::<u16>()
            .with_context(|| format!("invalid dns hijack port `{}`", port))?;
        return Ok(TunDnsHijackTarget::Any(port));
    }

    let addr = value
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid dns hijack address `{}`", value))?;
    Ok(TunDnsHijackTarget::Exact(addr))
}

#[cfg(test)]
mod tests {
    use super::{TunDnsHijackTarget, TunDnsHijackTransport, parse_tun_dns_hijack_spec};

    #[test]
    fn parses_default_udp_dns_hijack_rule() {
        let spec = parse_tun_dns_hijack_spec("any:53").unwrap();

        assert_eq!(spec.transport, TunDnsHijackTransport::Udp);
        assert_eq!(spec.target, TunDnsHijackTarget::Any(53));
    }

    #[test]
    fn parses_tcp_dns_hijack_rule() {
        let spec = parse_tun_dns_hijack_spec("tcp://any:53").unwrap();

        assert_eq!(spec.transport, TunDnsHijackTransport::Tcp);
        assert_eq!(spec.target, TunDnsHijackTarget::Any(53));
    }
}
