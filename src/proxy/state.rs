use super::executors::UpstreamExecutor;
use super::tls::TlsInterceptService;
use crate::plugins::LivePluginRegistry;
use crate::rules::pool::LiveRuleSet;

#[derive(Clone)]
pub(crate) struct AppState<E: UpstreamExecutor> {
    pub(crate) executor: E,
    pub(crate) tls_intercept: TlsInterceptService,
    pub(crate) plugins: LivePluginRegistry,
    pub(crate) rules: LiveRuleSet,
}
