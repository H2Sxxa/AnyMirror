pub mod shared;
pub mod tun;

#[cfg(target_os = "windows")]
pub mod windivert;

use std::net::SocketAddr;

use anyhow::Result;
use ipnet::{Ipv4Net, Ipv6Net};

use self::shared::FakeDnsServer;
use crate::config::{BackendOptions, TransparentBackendKind};
use crate::workers::Workers;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransparentInterceptRuntimeConfig {
    pub tls_port: Option<u16>,
    pub fake_ipv4_range: Ipv4Net,
    pub fake_ipv6_range: Ipv6Net,
}

pub struct TransparentInterceptHandle {
    inner: TransparentInterceptHandleInner,
}

enum TransparentInterceptHandleInner {
    Tun(tun::TransparentInterceptHandle),
    #[cfg(target_os = "windows")]
    WinDivert(windivert::TransparentInterceptHandle),
}

impl TransparentInterceptHandle {
    pub async fn shutdown(self) {
        match self.inner {
            TransparentInterceptHandleInner::Tun(handle) => handle.shutdown().await,
            #[cfg(target_os = "windows")]
            TransparentInterceptHandleInner::WinDivert(handle) => handle.shutdown().await,
        }
    }
}

pub fn run_transparent_intercept_backend(
    listen_addr: SocketAddr,
    tls_port: Option<u16>,
    backend: &BackendOptions,
    fake_dns_server: FakeDnsServer,
    workers: Workers,
) -> Result<TransparentInterceptHandle> {
    let runtime_config = TransparentInterceptRuntimeConfig {
        tls_port,
        fake_ipv4_range: backend.dns.fake_ipv4_range,
        fake_ipv6_range: backend.dns.fake_ipv6_range,
    };

    match backend.kind {
        TransparentBackendKind::Tun => tun::run_transparent_tun_runtimes(
            &runtime_config,
            &backend.tun,
            fake_dns_server,
            listen_addr,
            workers,
        )
        .map(|handle| TransparentInterceptHandle {
            inner: TransparentInterceptHandleInner::Tun(handle),
        }),
        TransparentBackendKind::WinDivert => {
            #[cfg(target_os = "windows")]
            {
                return windivert::run_transparent_windivert_runtimes(
                    &runtime_config,
                    &backend.windivert,
                    fake_dns_server,
                    listen_addr,
                    workers,
                )
                .map(|handle| TransparentInterceptHandle {
                    inner: TransparentInterceptHandleInner::WinDivert(handle),
                });
            }

            #[cfg(not(target_os = "windows"))]
            {
                let _ = (listen_addr, fake_dns_server, workers, runtime_config);
                anyhow::bail!(
                    "backend.kind=windivert is only supported on Windows; use backend.kind=tun for the experimental TUN backend"
                )
            }
        }
    }
}
