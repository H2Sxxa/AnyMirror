use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use super::super::{
    executor::UpstreamExecutor,
    request_parser::parse_request_url,
    responses::{json_error, rule_action_name, rule_kind_name, RewriteQuery, RewriteResponse},
    state::AppState,
};

pub(crate) async fn rewrite_url<E: UpstreamExecutor>(
    State(state): State<AppState<E>>,
    Query(query): Query<RewriteQuery>,
) -> Response {
    let original = match parse_request_url(&query.url) {
        Ok(url) => url,
        Err(response) => return response,
    };

    match state.rules.resolve(&original) {
        Some(matched) => Json(RewriteResponse {
            original: original.to_string(),
            rewritten: matched.upstream().map(|upstream| upstream.url.to_string()),
            action: rule_action_name(matched.clone()),
            kind: rule_kind_name(matched),
        })
        .into_response(),
        None => json_error(StatusCode::NOT_FOUND, "no matching mirror rule"),
    }
}
