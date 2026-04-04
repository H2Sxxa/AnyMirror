use anyhow::Result;

use crate::{
    config::FakeDnsOptions,
    rules::pool::LiveRules,
    traffic::shared::dns::{FakeDnsRuntimeHandle, FakeDnsServer},
    workers::Workers,
};

#[derive(Clone)]
pub struct FakeDnsSupervisor {
    workers: Workers,
}

pub struct FakeDnsInstance {
    pub server: FakeDnsServer,
    pub runtime: FakeDnsRuntimeHandle,
}

impl FakeDnsInstance {
    pub async fn shutdown(self) {
        self.runtime.shutdown().await;
    }
}

impl FakeDnsSupervisor {
    pub fn new(workers: Workers) -> Self {
        Self { workers }
    }

    pub async fn start(
        &self,
        options: FakeDnsOptions,
        rules: LiveRules,
    ) -> Result<FakeDnsInstance> {
        let server = FakeDnsServer::new(options, rules)?;
        let runtime = server.start_runtime(self.workers.clone()).await?;
        Ok(FakeDnsInstance { server, runtime })
    }
}
