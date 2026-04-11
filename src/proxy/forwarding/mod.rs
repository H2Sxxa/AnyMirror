mod plugin;

use axum::{
    body::Body,
    http::{HeaderMap, Method, StatusCode},
    response::Response,
};
use tracing::{Instrument, Span, field};
use url::Url;

use super::{
    executors::UpstreamExecutor,
    proxy_response::{build_passthrough_response, build_proxy_response},
    responses::{json_error, reject_response, rule_action_name, rule_kind_name},
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
    let request_span = Span::current();
    request_span.record("forwarding_source", source.unwrap_or("explicit"));
    request_span.record("original_url", field::display(original.as_str()));

    let forward_span = tracing::info_span!(
        "request.forward",
        mode = "explicit",
        source = source.unwrap_or("explicit"),
        original_url = %original,
        rule_matched = field::Empty,
        rule_kind = field::Empty,
        action = field::Empty,
        plugin = field::Empty,
        upstream_url = field::Empty,
        response_kind = field::Empty,
        response_status = field::Empty
    );

    async {
        let rules = state.rules.snapshot();
        let matched = rules.resolve(&original);
        match matched {
            Some(matched) => {
                let action_name = rule_action_name(matched.clone());
                let rule_kind = rule_kind_name(matched.clone());
                Span::current().record("rule_matched", true);
                Span::current().record("rule_kind", rule_kind);
                Span::current().record("action", action_name);
                request_span.record("action", action_name);

                let message = rule_action_message(matched.action_kind(), false);
                if let Some(reject) = matched.reject() {
                    Span::current().record("response_kind", "reject");
                    Span::current().record("response_status", reject.status);
                    tracing::info!(
                        original_url = %original,
                        reject_status = reject.status,
                        reject_message = %reject.message,
                        "{message}"
                    );
                    return reject_response(reject.status, &reject.message);
                }
                if let Some(plugin_name) = matched.plugin() {
                    Span::current().record("plugin", plugin_name);
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
                Span::current().record("upstream_url", field::display(upstream.url.as_str()));
                request_span.record("upstream_url", field::display(upstream.url.as_str()));
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

                let response_status = executed.response.status().as_u16();
                Span::current().record("response_status", response_status);

                match matched.action_kind() {
                    RuleActionKind::Mirror => {
                        Span::current().record("response_kind", "mirror");
                        build_proxy_response(executed.response, matched, source)
                    }
                    RuleActionKind::Direct => {
                        Span::current().record("response_kind", "direct");
                        build_passthrough_response(executed.response, source, original.as_str())
                    }
                    RuleActionKind::Plugin => {
                        unreachable!("plugin actions resolve before upstream execution")
                    }
                    RuleActionKind::Reject => {
                        unreachable!("reject returns before upstream execution")
                    }
                }
            }
            None => {
                let upstream = UpstreamPlan::direct(&original);
                Span::current().record("rule_matched", false);
                Span::current().record("action", "direct");
                Span::current().record("upstream_url", field::display(upstream.url.as_str()));
                Span::current().record("response_kind", "direct");
                request_span.record("action", "direct");
                request_span.record("upstream_url", field::display(upstream.url.as_str()));
                tracing::info!(
                    original_url = %original,
                    "Explicit request does not match a rule; forwarding directly"
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

                Span::current().record("response_status", executed.response.status().as_u16());
                build_passthrough_response(
                    executed.response,
                    source.or(Some("explicit-direct")),
                    original.as_str(),
                )
            }
        }
    }
    .instrument(forward_span)
    .await
}

pub(crate) async fn forward_intercepted_request<E: UpstreamExecutor>(
    state: &AppState<E>,
    method: Method,
    inbound_headers: &HeaderMap,
    body: Body,
    original: Url,
    source: &'static str,
) -> Response {
    let request_span = Span::current();
    request_span.record("forwarding_source", source);
    request_span.record("original_url", field::display(original.as_str()));

    let forward_span = tracing::info_span!(
        "request.forward",
        mode = source,
        source = source,
        original_url = %original,
        rule_matched = field::Empty,
        rule_kind = field::Empty,
        action = field::Empty,
        plugin = field::Empty,
        upstream_url = field::Empty,
        response_kind = field::Empty,
        response_status = field::Empty
    );

    async {
        let rules = state.rules.snapshot();
        let matched = rules.resolve(&original);
        match matched {
            Some(matched) => {
                let action_name = rule_action_name(matched.clone());
                let rule_kind = rule_kind_name(matched.clone());
                Span::current().record("rule_matched", true);
                Span::current().record("rule_kind", rule_kind);
                Span::current().record("action", action_name);
                request_span.record("action", action_name);

                let message = rule_action_message(matched.action_kind(), true);
                if let Some(reject) = matched.reject() {
                    Span::current().record("response_kind", "reject");
                    Span::current().record("response_status", reject.status);
                    tracing::info!(
                        original_url = %original,
                        reject_status = reject.status,
                        reject_message = %reject.message,
                        "{message}"
                    );
                    return reject_response(reject.status, &reject.message);
                }
                if let Some(plugin_name) = matched.plugin() {
                    Span::current().record("plugin", plugin_name);
                    return plugin::forward_plugin_request(
                        state,
                        method,
                        inbound_headers,
                        body,
                        original,
                        Some(source),
                        plugin_name,
                    )
                    .await;
                }

                let upstream = matched
                    .upstream()
                    .expect("mirror/direct actions must resolve to an upstream");
                Span::current().record("upstream_url", field::display(upstream.url.as_str()));
                request_span.record("upstream_url", field::display(upstream.url.as_str()));
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

                let response_status = executed.response.status().as_u16();
                Span::current().record("response_status", response_status);

                match matched.action_kind() {
                    RuleActionKind::Mirror => {
                        Span::current().record("response_kind", "mirror");
                        build_proxy_response(executed.response, matched, Some(source))
                    }
                    RuleActionKind::Direct => {
                        Span::current().record("response_kind", "direct");
                        build_passthrough_response(
                            executed.response,
                            Some(source),
                            original.as_str(),
                        )
                    }
                    RuleActionKind::Plugin => {
                        unreachable!("plugin actions resolve before upstream execution")
                    }
                    RuleActionKind::Reject => {
                        unreachable!("reject returns before upstream execution")
                    }
                }
            }
            None => {
                let upstream = UpstreamPlan::direct(&original);
                Span::current().record("rule_matched", false);
                Span::current().record("action", "direct");
                Span::current().record("upstream_url", field::display(upstream.url.as_str()));
                Span::current().record("response_kind", "direct");
                request_span.record("action", "direct");
                request_span.record("upstream_url", field::display(upstream.url.as_str()));
                tracing::info!(
                    original_url = %original,
                    "Intercepted request does not match a rule; forwarding directly"
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

                Span::current().record("response_status", executed.response.status().as_u16());
                build_passthrough_response(executed.response, Some(source), original.as_str())
            }
        }
    }
    .instrument(forward_span)
    .await
}

pub(crate) async fn forward_transparent_request<E: UpstreamExecutor>(
    state: &AppState<E>,
    method: Method,
    inbound_headers: &HeaderMap,
    body: Body,
    original: Url,
) -> Response {
    forward_intercepted_request(
        state,
        method,
        inbound_headers,
        body,
        original,
        "transparent",
    )
    .await
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
