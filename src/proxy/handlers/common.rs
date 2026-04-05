use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    response::Response,
};
use url::Url;

use super::super::{
    executor::UpstreamExecutor, forwarding::forward_request,
    request_parser::ensure_supported_method, responses::json_error, state::AppState,
};

pub(super) fn reject_connect_request(
    request: &Request<Body>,
    message: &'static str,
) -> Option<Response> {
    (request.method() == Method::CONNECT).then(|| json_error(StatusCode::NOT_IMPLEMENTED, message))
}

pub(super) fn ensure_forwardable_method(request: &Request<Body>) -> Result<(), Response> {
    ensure_supported_method(request.method())
}

pub(super) async fn forward_standard_request<E: UpstreamExecutor>(
    state: &AppState<E>,
    request: Request<Body>,
    original: Url,
    source: &'static str,
) -> Response {
    let (parts, body) = request.into_parts();

    forward_request(
        state,
        parts.method,
        &parts.headers,
        body,
        original,
        Some(source),
    )
    .await
}
