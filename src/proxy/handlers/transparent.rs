use axum::{body::Body, extract::State, http::HeaderValue, http::Request, response::Response};

use super::super::{
    executors::UpstreamExecutor,
    forwarding::forward_transparent_request,
    request_parser::{ORIGINAL_SCHEME_HEADER, resolve_transparent_target},
    state::AppState,
    tls::TlsIntercepted,
};
use super::common::reject_connect_request;

pub(crate) async fn transparent_entry<E: UpstreamExecutor>(
    State(state): State<AppState<E>>,
    request: Request<Body>,
) -> Response {
    if let Some(response) = reject_connect_request(
        &request,
        "transparent HTTPS interception is not enabled in this build",
    ) {
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

    forward_transparent_request(
        &state,
        request.method().clone(),
        &headers, // use our customized headers
        request.into_body(),
        original,
    )
    .await
}
