use axum::{
    body::Body,
    extract::State,
    http::HeaderValue,
    http::{Method, Request, StatusCode},
    response::Response,
};

use super::super::{
    executor::UpstreamExecutor,
    forwarding::forward_request,
    request_parser::{ensure_supported_method, resolve_transparent_target, ORIGINAL_SCHEME_HEADER},
    responses::json_error,
    state::AppState,
    tls::TlsIntercepted,
};

pub(crate) async fn transparent_entry<E: UpstreamExecutor>(
    State(state): State<AppState<E>>,
    request: Request<Body>,
) -> Response {
    if request.method() == Method::CONNECT {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "transparent HTTPS interception is not enabled in this build",
        );
    }

    if let Err(response) = ensure_supported_method(request.method()) {
        return response;
    }

    let scheme = if request.extensions().get::<TlsIntercepted>().is_some() {
        "https"
    } else {
        "http"
    };

    let mut headers = request.headers().clone();
    if !headers.contains_key(ORIGINAL_SCHEME_HEADER) {
        headers.insert(ORIGINAL_SCHEME_HEADER, HeaderValue::from_static(scheme));
    }

    let original = match resolve_transparent_target(&headers, request.uri()) {
        Ok(url) => url,
        Err(response) => return response,
    };

    forward_request(
        &state,
        request.method().clone(),
        &headers, // use our customized headers
        request.into_body(),
        original,
        Some("transparent"),
    )
    .await
}
