use anyhow::{Result, bail};

use crate::workers::Workers;

use super::TunRuntimeContext;

pub struct TransparentInterceptHandle;

impl TransparentInterceptHandle {
    pub async fn shutdown(self) {}
}

pub fn run_transparent_tun_system_runtime(
    context: TunRuntimeContext,
    workers: Workers,
) -> Result<TransparentInterceptHandle> {
    let _ = workers;

    bail!(
        "backend.kind=tun with backend.tun.stack=system is TODO (backend.tun.name={}, backend.tun.mtu={}, fake_ipv4_range={}, fake_ipv6_range={})",
        context.tun_name,
        context.tun_mtu,
        context.fake_ipv4_range,
        context.fake_ipv6_range
    )
}
