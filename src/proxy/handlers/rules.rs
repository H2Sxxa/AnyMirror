use axum::{
    Json,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::super::{
    executors::UpstreamExecutor, request_parser::parse_request_url, responses::json_error,
    state::AppState,
};
use crate::rules::pool::{RuleExplainPriorityGroup, RuleExplainWinner};

#[derive(Debug, Deserialize)]
pub(crate) struct RuleExplainQuery {
    pub(crate) url: String,
}

#[derive(Debug, Serialize)]
struct RuleExplainResponse {
    original: String,
    priority_groups: Vec<RuleExplainPriorityGroup>,
    final_match: Option<RuleExplainWinner>,
}

pub(crate) async fn explain_rules<E: UpstreamExecutor>(
    State(state): State<AppState<E>>,
    Query(query): Query<RuleExplainQuery>,
) -> Response {
    let original = match parse_request_url(&query.url) {
        Ok(url) => url,
        Err(response) => return response,
    };

    let rules = state.rules.snapshot();
    let explanation = rules.explain(&original);
    if explanation.priority_groups.is_empty() {
        return json_error(axum::http::StatusCode::NOT_FOUND, "no candidate rules");
    }

    Json(RuleExplainResponse {
        original: original.to_string(),
        priority_groups: explanation.priority_groups,
        final_match: explanation.final_match,
    })
    .into_response()
}
