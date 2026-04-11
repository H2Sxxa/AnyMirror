use std::convert::Infallible;
use std::time::Instant;

use axum::{body::Body, http::Request, response::Response};
use hyper::body::Incoming;
use tracing::Instrument;

use super::super::{
    forwarding::forward_intercepted_request,
    http::request_parser::{ConnectAuthority, resolve_explicit_https_target},
    routers::{make_http_request_span, record_http_response_span},
    state::AppState,
    upstream::executors::UpstreamExecutor,
};

pub(crate) async fn handle_explicit_connect_https_request<E: UpstreamExecutor>(
    state: AppState<E>,
    connect_target: ConnectAuthority,
    request: Request<Incoming>,
) -> Result<Response, Infallible> {
    let request_span = make_http_request_span(&request);
    let started_at = Instant::now();

    let response = async move {
        let (parts, body) = request.into_parts();
        let request = Request::from_parts(parts, Body::new(body));
        let original = match resolve_explicit_https_target(&connect_target, request.uri()) {
            Ok(url) => url,
            Err(response) => return response,
        };

        let mut headers = request.headers().clone();
        headers.insert(
            axum::http::header::HOST,
            connect_target
                .host_header()
                .parse()
                .expect("normalized host header should be valid"),
        );

        forward_intercepted_request(
            &state,
            request.method().clone(),
            &headers,
            request.into_body(),
            original,
            "explicit-https",
        )
        .await
    }
    .instrument(request_span.clone())
    .await;

    record_http_response_span(&response, started_at.elapsed(), &request_span);

    Ok(response)
}
