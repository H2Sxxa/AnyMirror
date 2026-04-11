use std::time::Duration;

use axum::{
    Router,
    http::{Request, Response},
    routing::get,
};
use tower_http::trace::TraceLayer;
use tracing::Span;

use super::{
    executors::UpstreamExecutor,
    handlers::{fetch::fetch_url, health::healthz, rewrite::rewrite_url},
    state::AppState,
};

pub(super) fn build_common_router<E: UpstreamExecutor>() -> Router<AppState<E>> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/rewrite", get(rewrite_url))
        .route("/fetch", get(fetch_url).head(fetch_url))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(make_http_request_span)
                .on_response(record_http_response_span),
        )
}

pub(super) fn make_http_request_span<B>(request: &Request<B>) -> Span {
    tracing::info_span!(
        "http.request",
        method = %request.method(),
        uri = %request.uri(),
        forwarding_source = tracing::field::Empty,
        original_url = tracing::field::Empty,
        upstream_url = tracing::field::Empty,
        action = tracing::field::Empty,
        status_code = tracing::field::Empty,
        latency_ms = tracing::field::Empty
    )
}

pub(super) fn record_http_response_span<B>(response: &Response<B>, latency: Duration, span: &Span) {
    let latency_ms = match u64::try_from(latency.as_millis()) {
        Ok(value) => value,
        Err(_) => u64::MAX,
    };

    span.record("status_code", response.status().as_u16());
    span.record("latency_ms", latency_ms);
}
