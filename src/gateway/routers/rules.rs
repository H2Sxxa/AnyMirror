use axum::{Router, routing::get};

use super::super::{
    handlers::rules::explain_rules, state::AppState, upstream::executors::UpstreamExecutor,
};

pub(super) fn router<E: UpstreamExecutor>() -> Router<AppState<E>> {
    Router::new().route("/rules/explain", get(explain_rules::<E>))
}
