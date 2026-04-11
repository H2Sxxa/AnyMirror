use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    response::Response,
};
use url::Url;

use super::super::{
    executors::UpstreamExecutor, forwarding::forward_request, responses::json_error,
    state::AppState,
};

pub(super) fn reject_connect_request(
    request: &Request<Body>,
    message: &'static str,
) -> Option<Response> {
    (request.method() == Method::CONNECT).then(|| json_error(StatusCode::NOT_IMPLEMENTED, message))
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

pub(super) async fn forward_explicit_request<E, P>(
    state: &AppState<E>,
    request: Request<Body>,
    source: &'static str,
    parse_original: P,
) -> Response
where
    E: UpstreamExecutor,
    P: FnOnce(&Request<Body>) -> Result<Url, Response>,
{
    let original = match parse_original(&request) {
        Ok(url) => url,
        Err(response) => return response,
    };

    forward_standard_request(state, request, original, source).await
}
