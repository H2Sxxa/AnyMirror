use axum::{Router, routing::get};

use super::{
    executor::UpstreamExecutor,
    handlers::{fetch::fetch_url, health::healthz, rewrite::rewrite_url},
    state::AppState,
};

pub(super) fn build_common_router<E: UpstreamExecutor>() -> Router<AppState<E>> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/rewrite", get(rewrite_url))
        .route("/fetch", get(fetch_url).head(fetch_url))
}
