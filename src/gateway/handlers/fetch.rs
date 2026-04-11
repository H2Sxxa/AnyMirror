use axum::{
    body::Body,
    extract::{Query, State},
    http::Request,
    response::Response,
};

use super::super::{
    http::{request_parser::parse_request_url, responses::RewriteQuery},
    state::AppState,
    upstream::executors::UpstreamExecutor,
};
use super::common::forward_standard_request;

pub(crate) async fn fetch_url<E: UpstreamExecutor>(
    State(state): State<AppState<E>>,
    Query(query): Query<RewriteQuery>,
    request: Request<Body>,
) -> Response {
    let original = match parse_request_url(&query.url) {
        Ok(url) => url,
        Err(response) => return response,
    };

    forward_standard_request(&state, request, original, "fetch").await
}
