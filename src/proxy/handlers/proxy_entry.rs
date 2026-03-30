use axum::{
    body::Body,
    extract::State,
    http::{Method, Request, StatusCode},
    response::Response,
};

use super::super::{
    executor::UpstreamExecutor,
    forwarding::forward_request,
    request_parser::{ensure_supported_method, parse_absolute_url},
    responses::json_error,
    state::AppState,
};

pub(crate) async fn proxy_entry<E: UpstreamExecutor>(
    State(state): State<AppState<E>>,
    request: Request<Body>,
) -> Response {
    if request.method() == Method::CONNECT {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "CONNECT is not supported in this build; use explicit URL rewriting instead",
        );
    }

    if let Err(response) = ensure_supported_method(request.method()) {
        return response;
    }

    let original = match parse_absolute_url(&request.uri().to_string()) {
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
        Some("proxy"),
    )
    .await
}
