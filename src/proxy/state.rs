use std::net::SocketAddr;
use std::sync::Arc;

use super::executor::UpstreamExecutor;
use crate::rules::pool::Rules;

#[derive(Clone)]
pub(crate) struct AppState<E: UpstreamExecutor> {
    pub(crate) executor: E,
    pub(crate) listen_addr: SocketAddr,
    pub(crate) rules: Arc<Rules>,
}
