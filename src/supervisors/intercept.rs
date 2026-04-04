use std::net::SocketAddr;

use anyhow::Result;

use crate::{
    config::BackendOptions,
    traffic::{
        TransparentInterceptHandle, run_transparent_intercept_backend, shared::FakeDnsServer,
    },
    workers::Workers,
};

#[derive(Clone)]
pub struct InterceptBackendSupervisor {
    workers: Workers,
}

pub struct InterceptBackendRuntimeConfig {
    pub listen_addr: SocketAddr,
    pub tls_port: Option<u16>,
    pub backend: BackendOptions,
    pub fake_dns_server: FakeDnsServer,
}

pub type InterceptBackendHandle = TransparentInterceptHandle;

impl InterceptBackendSupervisor {
    pub fn new(workers: Workers) -> Self {
        Self { workers }
    }

    pub async fn start(
        &self,
        config: InterceptBackendRuntimeConfig,
    ) -> Result<InterceptBackendHandle> {
        run_transparent_intercept_backend(
            config.listen_addr,
            config.tls_port,
            &config.backend,
            config.fake_dns_server,
            self.workers.clone(),
        )
    }
}
