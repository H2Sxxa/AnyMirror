use axum::{
    body::Body,
    http::{HeaderMap, Method, StatusCode},
    response::Response,
};
use url::Url;

use super::{
    executor::UpstreamExecutor,
    proxy_response::{build_passthrough_response, build_proxy_response},
    responses::json_error,
    state::AppState,
};
use crate::rules::UpstreamPlan;

pub(crate) async fn forward_request<E: UpstreamExecutor>(
    state: &AppState<E>,
    method: Method,
    inbound_headers: &HeaderMap,
    body: Body,
    original: Url,
    source: Option<&str>,
) -> Response {
    let matched = match state.rules.resolve(&original) {
        Some(matched) => matched,
        None => return json_error(StatusCode::NOT_FOUND, "no matching mirror rule"),
    };

    tracing::info!(
        "Forwarding {} to upstream mirror: {}",
        original,
        matched.upstream.url
    );
    let executed = match state
        .executor
        .execute(
            method,
            inbound_headers,
            original.as_str(),
            &matched.upstream,
            body,
        )
        .await
    {
        Ok(executed) => executed,
        Err(error) => {
            return json_error(
                StatusCode::BAD_GATEWAY,
                format!("upstream request failed: {error}"),
            );
        }
    };

    build_proxy_response(executed.response, matched, source)
}

pub(crate) async fn forward_transparent_request<E: UpstreamExecutor>(
    state: &AppState<E>,
    method: Method,
    inbound_headers: &HeaderMap,
    body: Body,
    original: Url,
) -> Response {
    let matched = state.rules.resolve(&original);
    match matched {
        Some(matched) => {
            tracing::info!(
                original_url = %original,
                upstream_url = %matched.upstream.url,
                "Forwarding transparent request to upstream mirror"
            );
            let executed = match state
                .executor
                .execute(
                    method,
                    inbound_headers,
                    original.as_str(),
                    &matched.upstream,
                    body,
                )
                .await
            {
                Ok(executed) => executed,
                Err(error) => {
                    return json_error(
                        StatusCode::BAD_GATEWAY,
                        format!("upstream request failed: {error}"),
                    );
                }
            };

            build_proxy_response(executed.response, matched, Some("transparent"))
        }
        None => {
            let upstream = direct_upstream_plan(&original);
            tracing::info!(
                original_url = %original,
                "Transparent request does not match a mirror rule; forwarding directly"
            );
            let executed = match state
                .executor
                .execute(method, inbound_headers, original.as_str(), &upstream, body)
                .await
            {
                Ok(executed) => executed,
                Err(error) => {
                    return json_error(
                        StatusCode::BAD_GATEWAY,
                        format!("direct upstream request failed: {error}"),
                    );
                }
            };

            build_passthrough_response(
                executed.response,
                Some("transparent-direct"),
                original.as_str(),
            )
        }
    }
}

fn direct_upstream_plan(original: &Url) -> UpstreamPlan {
    UpstreamPlan {
        url: original.clone(),
        sni: None,
        host: None,
        connect_host: None,
        connect_ip: None,
        dns: None,
    }
}
