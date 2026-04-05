use anyhow::Result;

use crate::{
    config::FakeDnsOptions,
    rules::pool::LiveRuleSet,
    traffic::shared::dns::{FakeDnsRuntimeHandle, FakeDnsServer},
    workers::Workers,
};

#[derive(Clone)]
pub struct FakeDnsSupervisor {
    workers: Workers,
}

pub struct FakeDnsInstance {
    pub server: FakeDnsServer,
    pub runtime: Option<FakeDnsRuntimeHandle>,
}

impl FakeDnsInstance {
    pub async fn shutdown(self) {
        if let Some(runtime) = self.runtime {
            runtime.shutdown().await;
        }
    }
}

impl FakeDnsSupervisor {
    pub fn new(workers: Workers) -> Self {
        Self { workers }
    }

    pub fn build(&self, options: FakeDnsOptions, rules: LiveRuleSet) -> Result<FakeDnsInstance> {
        let server = FakeDnsServer::new(options, rules)?;
        Ok(FakeDnsInstance {
            server,
            runtime: None,
        })
    }

    pub async fn start(
        &self,
        options: FakeDnsOptions,
        rules: LiveRuleSet,
    ) -> Result<FakeDnsInstance> {
        let server = FakeDnsServer::new(options, rules)?;
        let runtime = server.start_runtime(self.workers.clone()).await?;
        Ok(FakeDnsInstance {
            server,
            runtime: Some(runtime),
        })
    }
}
