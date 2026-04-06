use anyhow::{Context, Result};

use crate::{
    config::PluginRuntimeOptions,
    plugins::{LivePluginRegistry, PluginRegistry},
    rules::pool::LiveRuleSet,
    workers::Workers,
};

#[derive(Clone)]
pub struct PluginSupervisor {
    workers: Workers,
}

impl PluginSupervisor {
    pub fn new(workers: Workers) -> Self {
        Self { workers }
    }

    pub async fn start(
        &self,
        options: &PluginRuntimeOptions,
        rules: LiveRuleSet,
    ) -> Result<LivePluginRegistry> {
        let registry = self.build_registry(options, rules).await?;
        Ok(LivePluginRegistry::new(registry))
    }

    pub async fn reload(
        &self,
        live: &LivePluginRegistry,
        options: &PluginRuntimeOptions,
        rules: LiveRuleSet,
    ) -> Result<()> {
        let registry = self.build_registry(options, rules).await?;
        live.replace(registry);
        Ok(())
    }

    async fn build_registry(
        &self,
        options: &PluginRuntimeOptions,
        rules: LiveRuleSet,
    ) -> Result<PluginRegistry> {
        let rule_snapshot = rules.snapshot();
        PluginRegistry::build(options, rule_snapshot.as_ref(), &self.workers)
            .await
            .context("failed to build plugin registry")
    }
}
