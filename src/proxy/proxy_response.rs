use axum::{body::Body, http::HeaderName, response::Response};

use crate::rules::RuleMatch;

use super::{headers::is_forwardable_header, responses::rule_kind_name};

pub(super) fn build_proxy_response(
    upstream: hyper::Response<hyper::body::Incoming>,
    matched: RuleMatch<'_>,
    source: Option<&str>,
) -> Response {
    let status = upstream.status();
    let mut response = Response::builder().status(status);
    let response_headers = response.headers_mut().expect("response builder is valid");

    for (name, value) in upstream.headers() {
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
        matched
            .upstream
            .url
            .as_str()
            .parse()
            .unwrap_or_else(|_| "unavailable".parse().expect("fallback header is valid")),
    );
    response_headers.insert(
        HeaderName::from_static("x-anymirror-rule-kind"),
        rule_kind_name(matched)
            .parse()
            .expect("static header value is valid"),
    );

    // Convert hyper's Incoming body to axum's Body
    response
        .body(Body::new(upstream.into_body()))
        .expect("response body build should not fail")
}
