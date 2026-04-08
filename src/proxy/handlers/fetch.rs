use axum::{
    body::Body,
    extract::{Query, State},
    http::Request,
    response::Response,
};

use super::super::{
    executors::UpstreamExecutor, request_parser::parse_request_url, responses::RewriteQuery,
    state::AppState,
};
use super::common::{ensure_forwardable_method, forward_standard_request};

pub(crate) async fn fetch_url<E: UpstreamExecutor>(
    State(state): State<AppState<E>>,
    Query(query): Query<RewriteQuery>,
    request: Request<Body>,
) -> Response {
    if let Err(response) = ensure_forwardable_method(&request) {
        return response;
    }

    let original = match parse_request_url(&query.url) {
        Ok(url) => url,
        Err(response) => return response,
    };

    forward_standard_request(&state, request, original, "fetch").await
}
