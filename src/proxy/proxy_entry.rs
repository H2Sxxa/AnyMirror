use axum::{
    body::Body,
    extract::State,
    http::{Method, Request, StatusCode},
    response::Response,
};

use super::{
    forward::forward_request,
    shared::{ensure_supported_method, json_error, parse_absolute_url},
    state::AppState,
};

pub(crate) async fn proxy_entry(State(state): State<AppState>, request: Request<Body>) -> Response {
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

    forward_request(
        &state,
        request.method().clone(),
        request.headers(),
        original,
        Some("proxy"),
    )
    .await
}
