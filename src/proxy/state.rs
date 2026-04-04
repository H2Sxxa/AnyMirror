use std::net::SocketAddr;

use super::executor::UpstreamExecutor;
use crate::rules::pool::LiveRules;

#[derive(Clone)]
pub(crate) struct AppState<E: UpstreamExecutor> {
    pub(crate) executor: E,
    pub(crate) listen_addr: SocketAddr,
    pub(crate) rules: LiveRules,
}
