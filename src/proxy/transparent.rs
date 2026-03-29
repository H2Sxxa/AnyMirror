use axum::{
    body::Body,
    extract::State,
    http::{Method, Request, StatusCode},
    response::Response,
};

use super::{
    forward::forward_request,
    shared::{ensure_supported_method, json_error, resolve_transparent_target},
    state::AppState,
};

pub(crate) async fn transparent_entry(
    State(state): State<AppState>,
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

    let scheme = if request
        .extensions()
        .get::<crate::proxy::tls::TlsIntercepted>()
        .is_some()
    {
        "https"
    } else {
        "http"
    };

    let mut headers = request.headers().clone();
    if !headers.contains_key(super::shared::ORIGINAL_SCHEME_HEADER) {
        headers.insert(
            super::shared::ORIGINAL_SCHEME_HEADER,
            axum::http::HeaderValue::from_static(scheme),
        );
    }

    let original = match resolve_transparent_target(&headers, request.uri()) {
        Ok(url) => url,
        Err(response) => return response,
    };

    forward_request(
        &state,
        request.method().clone(),
        request.headers(),
        original,
        Some("transparent"),
    )
    .await
}
