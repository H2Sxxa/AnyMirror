use axum::{body::Body, http::HeaderName, response::Response};

use crate::rules::pool::MatchedRule;

use super::{headers::is_forwardable_header, responses::rule_kind_name};

pub(super) fn build_proxy_response(
    upstream: hyper::Response<hyper::body::Incoming>,
    matched: MatchedRule<'_>,
    source: Option<&str>,
) -> Response {
    let target = matched
        .upstream()
        .expect("mirror responses must have an upstream")
        .url
        .to_string();
    let rule_kind = rule_kind_name(matched);
    build_upstream_response(upstream, source, Some(&target), Some(rule_kind))
}

pub(super) fn build_passthrough_response(
    upstream: hyper::Response<hyper::body::Incoming>,
    source: Option<&str>,
    target: &str,
) -> Response {
    build_upstream_response(upstream, source, Some(target), None)
}

fn build_upstream_response(
    upstream: hyper::Response<hyper::body::Incoming>,
    source: Option<&str>,
    target: Option<&str>,
    rule_kind: Option<&str>,
) -> Response {
    let status = upstream.status();
    let mut response = Response::builder().status(status);
    let response_headers = response.headers_mut().expect("response builder is valid");

    for (name, value) in upstream.headers() {
        if is_forwardable_header(name) {
            response_headers.append(name, value.clone());
        }
    }

    if let Some(source) = source {
        response_headers.insert(
            HeaderName::from_static("x-anymirror-mode"),
            source.parse().expect("static header value is valid"),
        );
    }
    if let Some(target) = target {
        response_headers.insert(
            HeaderName::from_static("x-anymirror-target"),
            target
                .parse()
                .unwrap_or_else(|_| "unavailable".parse().expect("fallback header is valid")),
        );
    }
    if let Some(rule_kind) = rule_kind {
        response_headers.insert(
            HeaderName::from_static("x-anymirror-rule-kind"),
            rule_kind.parse().expect("static header value is valid"),
        );
    }

    // Convert hyper's Incoming body to axum's Body
    response
        .body(Body::new(upstream.into_body()))
        .expect("response body build should not fail")
}
