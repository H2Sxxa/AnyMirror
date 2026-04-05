use axum::{body::Body, extract::State, http::Request, response::Response};

use super::super::{
    executor::UpstreamExecutor, request_parser::parse_absolute_url, state::AppState,
};
use super::common::{ensure_forwardable_method, forward_standard_request, reject_connect_request};

pub(crate) async fn proxy_entry<E: UpstreamExecutor>(
    State(state): State<AppState<E>>,
    request: Request<Body>,
) -> Response {
    if let Some(response) = reject_connect_request(
        &request,
        "CONNECT is not supported in this build; use explicit URL rewriting instead",
    ) {
        return response;
    }

    if let Err(response) = ensure_forwardable_method(&request) {
        return response;
    }

    let original = match parse_absolute_url(&request.uri().to_string()) {
        Ok(url) => url,
        Err(response) => return response,
    };

    forward_standard_request(&state, request, original, "proxy").await
}
