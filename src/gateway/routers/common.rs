use axum::{Router, routing::get};

use super::super::{
    handlers::health::healthz, state::AppState, upstream::executors::UpstreamExecutor,
};

pub(super) fn router<E: UpstreamExecutor>() -> Router<AppState<E>> {
    Router::new().route("/healthz", get(healthz))
}
