use std::net::SocketAddr;
use std::sync::Arc;

use reqwest::Client;

use crate::rules::Rules;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) client: Client,
    pub(crate) listen_addr: SocketAddr,
    pub(crate) rules: Arc<Rules>,
}
