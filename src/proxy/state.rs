use super::executor::UpstreamExecutor;
use crate::rules::pool::LiveRuleSet;

#[derive(Clone)]
pub(crate) struct AppState<E: UpstreamExecutor> {
    pub(crate) executor: E,
    pub(crate) rules: LiveRuleSet,
}
