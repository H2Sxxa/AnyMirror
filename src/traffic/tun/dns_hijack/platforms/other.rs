use std::io;
use std::sync::Arc;

use tun_rs::AsyncDevice;

use crate::traffic::tun::TunRuntimeContext;

pub(super) fn configure(_device: Arc<AsyncDevice>, context: &TunRuntimeContext) -> io::Result<()> {
    Err(io::Error::other(format!(
        "automatic TUN DNS configuration is not implemented for this platform; switch backend.tun.platform_dns to manual and point the TUN interface DNS at {}, {}",
        context.dns_plan.dns_addr_v4, context.dns_plan.dns_addr_v6
    )))
}
