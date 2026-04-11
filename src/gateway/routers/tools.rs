use axum::{Router, routing::get};

use super::super::{
    handlers::{fetch::fetch_url, rewrite::rewrite_url},
    state::AppState,
    upstream::executors::UpstreamExecutor,
};

pub(super) fn router<E: UpstreamExecutor>() -> Router<AppState<E>> {
    Router::new()
        .route("/tools/rewrite", get(rewrite_url))
        .route("/tools/fetch", get(fetch_url).head(fetch_url))
}
