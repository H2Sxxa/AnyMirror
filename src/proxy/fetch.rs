use axum::{
    body::Body,
    extract::{Query, State},
    http::Request,
    response::Response,
};

use super::{
    forward::forward_request,
    shared::{RewriteQuery, ensure_supported_method, parse_request_url},
    state::AppState,
};

pub(crate) async fn fetch_url(
    State(state): State<AppState>,
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

    forward_request(
        &state,
        request.method().clone(),
        request.headers(),
        original,
        Some("query"),
    )
    .await
}
