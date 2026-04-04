use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use tokio::signal;

use crate::rules::pool::RuleMatch;
use crate::rules::types::{RuleActionKind, RuleKind};

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

pub(crate) fn rule_kind_name(matched: RuleMatch<'_>) -> &'static str {
    match matched.rule.kind {
        RuleKind::Exact => "exact",
        RuleKind::Prefix => "prefix",
        RuleKind::Host => "host",
        RuleKind::Hosts => "hosts",
        RuleKind::HostSuffix => "host-suffix",
    }
}

pub(crate) fn rule_action_name(matched: RuleMatch<'_>) -> &'static str {
    match matched.action_kind() {
        RuleActionKind::Mirror => "mirror",
        RuleActionKind::Direct => "direct",
        RuleActionKind::Reject => "reject",
    }
}

pub(crate) fn reject_response(status: u16, message: &str) -> Response {
    let status = StatusCode::from_u16(status).expect("validated reject status");
    json_error(status, message)
}

pub(crate) async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
}
