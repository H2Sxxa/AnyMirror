use axum::{
    body::Body,
    http::{
        HeaderMap, HeaderName, Method, StatusCode,
        header::{
            CONNECTION, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER,
            TRANSFER_ENCODING, UPGRADE,
        },
    },
    response::Response,
};
use url::Url;

use crate::rules::Rewrite;

use super::{
    shared::{json_error, rule_kind_name},
    state::AppState,
};

pub(crate) async fn forward_request(
    state: &AppState,
    method: Method,
    inbound_headers: &HeaderMap,
    original: Url,
    source: Option<&str>,
) -> Response {
    let rewrite = match state.rules.rewrite(&original) {
        Some(rewrite) => rewrite,
        None => return json_error(StatusCode::NOT_FOUND, "no matching mirror rule"),
    };

    tracing::info!("Forwarding request to upstream mirror: {}", rewrite.target);
    let mut outbound = state.client.request(method, rewrite.target.clone());
    for (name, value) in inbound_headers {
        if is_forwardable_header(name) {
            outbound = outbound.header(name, value);
        }
    }
    outbound = outbound.header("x-anymirror-original-url", original.as_str());

    let upstream = match outbound.send().await {
        Ok(response) => response,
        Err(error) => {
            return json_error(
                StatusCode::BAD_GATEWAY,
                format!("upstream request failed: {error}"),
            );
        }
    };

    build_response(upstream, rewrite, source)
}

fn build_response(
    upstream: reqwest::Response,
    rewrite: Rewrite<'_>,
    source: Option<&str>,
) -> Response {
    let status = upstream.status();
    let headers = upstream.headers().clone();
    let stream = upstream.bytes_stream();
    let mut response = Response::builder().status(status);
    let response_headers = response.headers_mut().expect("response builder is valid");

    for (name, value) in &headers {
        if is_forwardable_header(name) {
            response_headers.insert(name, value.clone());
        }
    }

    if let Some(source) = source {
        response_headers.insert(
            HeaderName::from_static("x-anymirror-mode"),
            source.parse().expect("static header value is valid"),
        );
    }
    response_headers.insert(
        HeaderName::from_static("x-anymirror-target"),
        rewrite
            .target
            .as_str()
            .parse()
            .unwrap_or_else(|_| "unavailable".parse().expect("fallback header is valid")),
    );
    response_headers.insert(
        HeaderName::from_static("x-anymirror-rule-kind"),
        rule_kind_name(rewrite)
            .parse()
            .expect("static header value is valid"),
    );

    response
        .body(Body::from_stream(stream))
        .expect("response body build should not fail")
}

fn is_forwardable_header(name: &HeaderName) -> bool {
    *name != HOST
        && *name != CONNECTION
        && *name != HeaderName::from_static("keep-alive")
        && *name != PROXY_AUTHENTICATE
        && *name != PROXY_AUTHORIZATION
        && *name != HeaderName::from_static("proxy-connection")
        && *name != TE
        && *name != TRAILER
        && *name != TRANSFER_ENCODING
        && *name != UPGRADE
}
