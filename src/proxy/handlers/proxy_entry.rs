use axum::{body::Body, extract::State, http::Request, response::Response};

use super::super::{
    executors::UpstreamExecutor, request_parser::parse_absolute_url, state::AppState,
};
use super::common::forward_explicit_request;

pub(crate) async fn proxy_entry<E: UpstreamExecutor>(
    State(state): State<AppState<E>>,
    request: Request<Body>,
) -> Response {
    forward_explicit_request(
        &state,
        request,
        "proxy",
        "CONNECT is not supported in this build; use explicit URL rewriting instead",
        |request| parse_absolute_url(&request.uri().to_string()),
    )
    .await
}
