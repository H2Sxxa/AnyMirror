mod resolvectl;

use std::io;
use std::sync::Arc;

use tun_rs::AsyncDevice;

use crate::traffic::tun::TunRuntimeContext;

pub(super) enum LinuxPlatformDnsGuard {
    Resolvectl(resolvectl::ResolvectlDnsGuard),
}

impl LinuxPlatformDnsGuard {
    pub(super) fn restore(self) -> io::Result<()> {
        match self {
            Self::Resolvectl(guard) => guard.restore(),
        }
    }
}

pub(super) fn configure(
    device: Arc<AsyncDevice>,
    context: &TunRuntimeContext,
) -> io::Result<LinuxPlatformDnsGuard> {
    tracing::info!(
        tun_name = %context.tun_name,
        tun_dns_ipv4 = %context.dns_plan.dns_addr_v4,
        tun_dns_ipv6 = %context.dns_plan.dns_addr_v6,
        "Configuring Linux TUN DNS automation with resolvectl"
    );

    resolvectl::configure(device, context).map(LinuxPlatformDnsGuard::Resolvectl)
}
