use axum::{Router, routing::get};

use super::super::{
    handlers::observability::{recent_events, runtime_state},
    state::AppState,
    upstream::executors::UpstreamExecutor,
};

pub(super) fn router<E: UpstreamExecutor>() -> Router<AppState<E>> {
    Router::new()
        .route("/observability/events", get(recent_events::<E>))
        .route("/observability/state", get(runtime_state::<E>))
}
