mod common;
mod observability;
mod rules;
mod tools;
mod trace;

use axum::Router;
use tower_http::trace::TraceLayer;

use super::{state::AppState, upstream::executors::UpstreamExecutor};

pub(crate) use trace::{make_http_request_span, record_http_response_span};

pub(super) fn build_common_router<E: UpstreamExecutor>() -> Router<AppState<E>> {
    Router::new()
        .merge(common::router::<E>())
        .merge(observability::router::<E>())
        .merge(rules::router::<E>())
        .merge(tools::router::<E>())
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(make_http_request_span)
                .on_response(record_http_response_span),
        )
}
