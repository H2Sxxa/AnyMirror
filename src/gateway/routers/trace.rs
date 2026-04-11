use std::time::Duration;

use axum::http::{Request, Response};
use tracing::Span;

pub(crate) fn make_http_request_span<B>(request: &Request<B>) -> Span {
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

pub(crate) fn record_http_response_span<B>(response: &Response<B>, latency: Duration, span: &Span) {
    let latency_ms = match u64::try_from(latency.as_millis()) {
        Ok(value) => value,
        Err(_) => u64::MAX,
    };

    span.record("status_code", response.status().as_u16());
    span.record("latency_ms", latency_ms);
}
