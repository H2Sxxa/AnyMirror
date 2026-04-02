use std::{fs, net::SocketAddr, path::Path};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::rules::Rules;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub listen_addr: SocketAddr,
    pub tls_port: Option<u16>,
    pub windivert: WinDivertOptions,
    pub rules: Rules,
}

#[derive(Debug, Clone, Default)]
pub struct WinDivertOptions {
    pub hot_reload: bool,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default = "default_listen_addr")]
    listen: String,
    tls_port: Option<u16>,
    #[serde(default)]
    windivert: RawWinDivertOptions,
    #[serde(default, alias = "rules")]
    includes: Vec<crate::rules::RawRule>,
    #[allow(dead_code)]
    #[serde(default)]
    classes: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RawWinDivertOptions {
    #[serde(default)]
    hot_reload: bool,
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
        windivert: WinDivertOptions::from(parsed.windivert),
        rules,
    })
}

fn default_listen_addr() -> String {
    "127.0.0.1:8787".to_string()
}

impl From<RawWinDivertOptions> for WinDivertOptions {
    fn from(value: RawWinDivertOptions) -> Self {
        Self {
            hot_reload: value.hot_reload,
        }
    }
}
