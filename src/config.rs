use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use ipnet::{Ipv4Net, Ipv6Net};
use serde::Deserialize;

use crate::rules::pool::Rules;
use crate::rules::schema::RawRule;
use crate::traffic::windivert::WinDivertLayer;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub listen_addr: SocketAddr,
    pub tls_port: Option<u16>,
    pub backend: BackendOptions,
    pub rules: Rules,
}

#[derive(Debug, Clone)]
pub struct BackendOptions {
    pub dns: FakeDnsOptions,
    pub windivert: WinDivertBackendOptions,
}

#[derive(Debug, Clone)]
pub struct WinDivertBackendOptions {
    pub layer: WinDivertLayer,
}

#[derive(Debug, Clone)]
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
    includes: Vec<RawRule>,
}

#[derive(Debug, Deserialize, Default)]
struct RawBackendOptions {
    #[serde(default)]
    dns: RawFakeDnsOptions,
    #[serde(default)]
    windivert: RawWinDivertBackendOptions,
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
    let rules = Rules::try_from(parsed.includes)?;

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
            dns: FakeDnsOptions::try_from(value.dns)?,
            windivert: WinDivertBackendOptions::try_from(value.windivert)?,
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

fn default_backend_dns_listen_addr() -> String {
    "127.0.0.1:15353".to_string()
}

fn default_windivert_layer() -> String {
    "network".to_string()
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

fn parse_windivert_layer(value: &str) -> Result<WinDivertLayer> {
    match value {
        "network" => Ok(WinDivertLayer::Network),
        "network-forward" | "network_forward" => Ok(WinDivertLayer::NetworkForward),
        _ => bail!(
            "invalid backend.windivert.layer `{}` (expected `network` or `network-forward`)",
            value
        ),
    }
}
