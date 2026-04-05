mod dns_hijack;
mod smoltcp;
mod system;

use std::net::SocketAddr;

use anyhow::Result;
use ipnet::{Ipv4Net, Ipv6Net};

use crate::config::{TunBackendOptions, TunDnsHijackSpec, TunPlatformDnsMode, TunStack};
use crate::traffic::TransparentInterceptRuntimeConfig;
use crate::traffic::shared::dns::FakeDnsServer;
use crate::workers::Workers;

use self::dns_hijack::{TunDnsPlan, TunDnsTransport};

#[derive(Clone)]
pub(super) struct TunRuntimeContext {
    pub tun_name: String,
    pub tun_mtu: u16,
    pub proxy_redirect_addr: SocketAddr,
    pub tls_port: u16,
    pub fake_ipv4_range: Ipv4Net,
    pub fake_ipv6_range: Ipv6Net,
    pub fake_dns_server: FakeDnsServer,
    pub platform_dns: TunPlatformDnsMode,
    dns_plan: TunDnsPlan,
    dns_hijack: Vec<TunDnsHijackSpec>,
}

pub struct TransparentInterceptHandle {
    inner: TransparentInterceptHandleInner,
}

enum TransparentInterceptHandleInner {
    System(system::TransparentInterceptHandle),
    Smoltcp(smoltcp::TransparentInterceptHandle),
}

impl TransparentInterceptHandle {
    pub async fn shutdown(self) {
        match self.inner {
            TransparentInterceptHandleInner::System(handle) => handle.shutdown().await,
            TransparentInterceptHandleInner::Smoltcp(handle) => handle.shutdown().await,
        }
    }
}

pub fn run_transparent_tun_runtimes(
    runtime_config: &TransparentInterceptRuntimeConfig,
    backend: &TunBackendOptions,
    fake_dns_server: FakeDnsServer,
    proxy_redirect_addr: SocketAddr,
    workers: Workers,
) -> Result<TransparentInterceptHandle> {
    let context = TunRuntimeContext::new(
        runtime_config,
        backend,
        fake_dns_server,
        proxy_redirect_addr,
    );

    match backend.stack {
        TunStack::System => {
            system::run_transparent_tun_system_runtime(context, workers).map(|handle| {
                TransparentInterceptHandle {
                    inner: TransparentInterceptHandleInner::System(handle),
                }
            })
        }
        TunStack::Smoltcp => {
            smoltcp::run_transparent_tun_smoltcp_runtime(context, workers).map(|handle| {
                TransparentInterceptHandle {
                    inner: TransparentInterceptHandleInner::Smoltcp(handle),
                }
            })
        }
    }
}

impl TunRuntimeContext {
    fn new(
        runtime_config: &TransparentInterceptRuntimeConfig,
        backend: &TunBackendOptions,
        fake_dns_server: FakeDnsServer,
        proxy_redirect_addr: SocketAddr,
    ) -> Self {
        let tls_port = runtime_config
            .tls_port
            .unwrap_or(proxy_redirect_addr.port() + 1);
        let dns_plan = TunDnsPlan::new(
            runtime_config.fake_ipv4_range,
            runtime_config.fake_ipv6_range,
        );

        Self {
            tun_name: backend.name.clone(),
            tun_mtu: backend.mtu,
            proxy_redirect_addr,
            tls_port,
            fake_ipv4_range: runtime_config.fake_ipv4_range,
            fake_ipv6_range: runtime_config.fake_ipv6_range,
            fake_dns_server,
            platform_dns: backend.platform_dns,
            dns_plan,
            dns_hijack: backend.dns_hijack.clone(),
        }
    }

    fn should_hijack_dns(&self, transport: TunDnsTransport, target_addr: SocketAddr) -> bool {
        self.dns_plan
            .should_hijack_dns(&self.dns_hijack, transport, target_addr)
    }
}
