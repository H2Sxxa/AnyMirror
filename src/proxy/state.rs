use super::executor::UpstreamExecutor;
use crate::rules::pool::LiveRules;

#[derive(Clone)]
pub(crate) struct AppState<E: UpstreamExecutor> {
    pub(crate) executor: E,
    pub(crate) rules: LiveRules,
}
