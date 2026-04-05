use std::io;
use std::sync::Arc;

use tun_rs::AsyncDevice;

use crate::traffic::tun::TunRuntimeContext;

pub(super) fn configure(device: Arc<AsyncDevice>, context: &TunRuntimeContext) -> io::Result<()> {
    let interface_name = device.name().unwrap_or_else(|_| context.tun_name.clone());

    Err(io::Error::other(format!(
        "automatic macOS TUN DNS configuration is not implemented for interface {}; configure DNS manually or use a NetworkExtension host (desired DNS: {}, {})",
        interface_name, context.dns_plan.dns_addr_v4, context.dns_plan.dns_addr_v6
    )))
}
