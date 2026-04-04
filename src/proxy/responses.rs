use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use tokio::signal;

use crate::rules::{RuleKind, RuleMatch};

#[derive(Debug, Deserialize)]
pub(crate) struct RewriteQuery {
    pub(crate) url: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct RewriteResponse {
    pub(crate) original: String,
    pub(crate) rewritten: String,
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
    }
}

pub(crate) async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
}
