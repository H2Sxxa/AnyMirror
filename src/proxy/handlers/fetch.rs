use axum::{
    body::Body,
    extract::{Query, State},
    http::Request,
    response::Response,
};

use super::super::{
    executor::UpstreamExecutor,
    forwarding::forward_request,
    request_parser::{ensure_supported_method, parse_request_url},
    responses::RewriteQuery,
    state::AppState,
};

pub(crate) async fn fetch_url<E: UpstreamExecutor>(
    State(state): State<AppState<E>>,
    Query(query): Query<RewriteQuery>,
    request: Request<Body>,
) -> Response {
    if let Err(response) = ensure_supported_method(request.method()) {
        return response;
    }

    let original = match parse_request_url(&query.url) {
        Ok(url) => url,
        Err(response) => return response,
    };

    let (parts, body) = request.into_parts();

    forward_request(
        &state,
        parts.method,
        &parts.headers,
        body,
        original,
        Some("fetch"),
    )
    .await
}
