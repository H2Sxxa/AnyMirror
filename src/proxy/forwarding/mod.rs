mod plugin;

use axum::{
    body::Body,
    http::{HeaderMap, Method, StatusCode},
    response::Response,
};
use url::Url;

use super::{
    executor::UpstreamExecutor,
    proxy_response::{build_passthrough_response, build_proxy_response},
    responses::{json_error, reject_response},
    state::AppState,
};
use crate::rules::model::{RuleActionKind, UpstreamPlan};

pub(crate) async fn forward_request<E: UpstreamExecutor>(
    state: &AppState<E>,
    method: Method,
    inbound_headers: &HeaderMap,
    body: Body,
    original: Url,
    source: Option<&str>,
) -> Response {
    let rules = state.rules.snapshot();
    let matched = match rules.resolve(&original) {
        Some(matched) => matched,
        None => return json_error(StatusCode::NOT_FOUND, "no matching mirror rule"),
    };

    let message = rule_action_message(matched.action_kind(), false);
    if let Some(reject) = matched.reject() {
        tracing::info!(
            original_url = %original,
            reject_status = reject.status,
            reject_message = %reject.message,
            "{message}"
        );
        return reject_response(reject.status, &reject.message);
    }
    if let Some(plugin_name) = matched.plugin() {
        return plugin::forward_plugin_request(
            state,
            method,
            inbound_headers,
            body,
            original,
            source,
            plugin_name,
        )
        .await;
    }

    let upstream = matched
        .upstream()
        .expect("mirror/direct actions must resolve to an upstream");
    tracing::info!(original_url = %original, upstream_url = %upstream.url, "{message}");
    let executed = match state
        .executor
        .execute(method, inbound_headers, original.as_str(), upstream, body)
        .await
    {
        Ok(executed) => executed,
        Err(error) => {
            return json_error(
                StatusCode::BAD_GATEWAY,
                format!("request forwarding failed: {error}"),
            );
        }
    };

    match matched.action_kind() {
        RuleActionKind::Mirror => build_proxy_response(executed.response, matched, source),
        RuleActionKind::Direct => {
            build_passthrough_response(executed.response, source, original.as_str())
        }
        RuleActionKind::Plugin => unreachable!("plugin actions resolve before upstream execution"),
        RuleActionKind::Reject => unreachable!("reject returns before upstream execution"),
    }
}

pub(crate) async fn forward_transparent_request<E: UpstreamExecutor>(
    state: &AppState<E>,
    method: Method,
    inbound_headers: &HeaderMap,
    body: Body,
    original: Url,
) -> Response {
    let rules = state.rules.snapshot();
    let matched = rules.resolve(&original);
    match matched {
        Some(matched) => {
            let message = rule_action_message(matched.action_kind(), true);
            if let Some(reject) = matched.reject() {
                tracing::info!(
                    original_url = %original,
                    reject_status = reject.status,
                    reject_message = %reject.message,
                    "{message}"
                );
                return reject_response(reject.status, &reject.message);
            }
            if let Some(plugin_name) = matched.plugin() {
                return plugin::forward_plugin_request(
                    state,
                    method,
                    inbound_headers,
                    body,
                    original,
                    Some("transparent"),
                    plugin_name,
                )
                .await;
            }

            let upstream = matched
                .upstream()
                .expect("mirror/direct actions must resolve to an upstream");
            tracing::info!(original_url = %original, upstream_url = %upstream.url, "{message}");
            let executed = match state
                .executor
                .execute(method, inbound_headers, original.as_str(), upstream, body)
                .await
            {
                Ok(executed) => executed,
                Err(error) => {
                    return json_error(
                        StatusCode::BAD_GATEWAY,
                        format!("request forwarding failed: {error}"),
                    );
                }
            };

            match matched.action_kind() {
                RuleActionKind::Mirror => {
                    build_proxy_response(executed.response, matched, Some("transparent"))
                }
                RuleActionKind::Direct => build_passthrough_response(
                    executed.response,
                    Some("transparent-direct"),
                    original.as_str(),
                ),
                RuleActionKind::Plugin => {
                    unreachable!("plugin actions resolve before upstream execution")
                }
                RuleActionKind::Reject => unreachable!("reject returns before upstream execution"),
            }
        }
        None => {
            let upstream = UpstreamPlan::direct(&original);
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

fn rule_action_message(action_kind: RuleActionKind, transparent: bool) -> &'static str {
    match (transparent, action_kind) {
        (false, RuleActionKind::Mirror) => "Forwarding request to upstream mirror",
        (false, RuleActionKind::Direct) => {
            "Forwarding request directly due to matching direct rule"
        }
        (false, RuleActionKind::Plugin) => "Resolving request through plugin action",
        (false, RuleActionKind::Reject) => "Rejecting request due to matching reject rule",
        (true, RuleActionKind::Mirror) => "Forwarding transparent request to upstream mirror",
        (true, RuleActionKind::Direct) => {
            "Forwarding transparent request directly due to matching direct rule"
        }
        (true, RuleActionKind::Plugin) => "Resolving transparent request through plugin action",
        (true, RuleActionKind::Reject) => {
            "Rejecting transparent request due to matching reject rule"
        }
    }
}
