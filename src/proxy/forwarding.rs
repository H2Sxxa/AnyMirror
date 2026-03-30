use axum::{
    body::Body,
    http::{HeaderMap, Method, StatusCode},
    response::Response,
};
use url::Url;

use super::{
    executor::UpstreamExecutor, proxy_response::build_proxy_response, responses::json_error,
    state::AppState,
};

pub(crate) async fn forward_request<E: UpstreamExecutor>(
    state: &AppState<E>,
    method: Method,
    inbound_headers: &HeaderMap,
    body: Body,
    original: Url,
    source: Option<&str>,
) -> Response {
    let matched = match state.rules.resolve(&original) {
        Some(matched) => matched,
        None => return json_error(StatusCode::NOT_FOUND, "no matching mirror rule"),
    };

    tracing::info!(
        "Forwarding {} to upstream mirror: {}",
        original,
        matched.upstream.url
    );
    let executed = match state
        .executor
        .execute(
            method,
            inbound_headers,
            original.as_str(),
            &matched.upstream,
            body,
        )
        .await
    {
        Ok(executed) => executed,
        Err(error) => {
            return json_error(
                StatusCode::BAD_GATEWAY,
                format!("upstream request failed: {error}"),
            );
        }
    };

    build_proxy_response(executed.response, matched, source)
}
