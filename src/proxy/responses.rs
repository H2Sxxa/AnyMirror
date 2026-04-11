use axum::{
    Json,
    body::Body,
    http::{HeaderValue, StatusCode, header::CONTENT_LENGTH},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::signal;

use crate::rules::model::{RespondBodySource, RespondRuleAction, RuleActionKind, RuleKind};
use crate::rules::pool::MatchedRule;

#[derive(Debug, Deserialize)]
pub(crate) struct RewriteQuery {
    pub(crate) url: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct RewriteResponse {
    pub(crate) original: String,
    pub(crate) rewritten: Option<String>,
    pub(crate) action: &'static str,
    pub(crate) kind: &'static str,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

pub(crate) fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: message.into(),
        }),
    )
        .into_response()
}

pub(crate) fn rule_kind_name(matched: MatchedRule<'_>) -> &'static str {
    match matched.rule.kind {
        RuleKind::Exact => "exact",
        RuleKind::Prefix => "prefix",
        RuleKind::Host => "host",
        RuleKind::Hosts => "hosts",
        RuleKind::HostSuffix => "host-suffix",
        RuleKind::Ip => "ip",
        RuleKind::IpCidr => "ip-cidr",
    }
}

pub(crate) fn rule_action_name(matched: MatchedRule<'_>) -> &'static str {
    match matched.action_kind() {
        RuleActionKind::Mirror => "mirror",
        RuleActionKind::Direct => "direct",
        RuleActionKind::Respond => "respond",
        RuleActionKind::Plugin => "plugin",
        RuleActionKind::Reject => "reject",
    }
}

pub(crate) async fn respond_response(action: &RespondRuleAction) -> Response {
    let status = StatusCode::from_u16(action.status).expect("validated respond status");
    let body = match load_respond_body(action).await {
        Ok(body) => body,
        Err(error) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to read respond body: {error}"),
            );
        }
    };
    let mut response = Response::builder().status(status);
    let response_headers = response.headers_mut().expect("response builder is valid");

    for (name, value) in &action.headers {
        response_headers.append(name, value.clone());
    }

    response_headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&body.len().to_string())
            .expect("response content length should be valid"),
    );

    response
        .body(Body::from(body))
        .expect("response body build should not fail")
}

async fn load_respond_body(action: &RespondRuleAction) -> std::io::Result<Bytes> {
    match &action.body {
        RespondBodySource::Inline(bytes) => Ok(bytes.clone()),
        RespondBodySource::File(path) => tokio::fs::read(path).await.map(Bytes::from),
    }
}

pub(crate) fn reject_response(status: u16, message: &str) -> Response {
    let status = StatusCode::from_u16(status).expect("validated reject status");
    json_error(status, message)
}

pub(crate) async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
    }
}
