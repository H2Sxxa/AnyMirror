pub mod shared;

#[cfg(target_os = "windows")]
pub mod windivert;

#[cfg(not(target_os = "windows"))]
pub mod windivert {
    use std::net::SocketAddr;

    use anyhow::{bail, Result};

    use crate::config::AppConfig;
    use crate::traffic::shared::FakeDnsServer;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum WinDivertLayer {
        Network,
        NetworkForward,
    }

    pub fn run_transparent_windivert_runtimes(
        _config: &AppConfig,
        _fake_dns_server: FakeDnsServer,
        _proxy_redirect_addr: SocketAddr,
    ) -> Result<()> {
        bail!("WinDivert transparent mode is only supported on Windows")
    }
}
