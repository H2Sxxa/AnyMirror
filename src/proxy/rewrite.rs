use axum::{
    Json,
    extract::{Query, State},
    response::{IntoResponse, Response},
};

use super::{
    shared::{RewriteQuery, RewriteResponse, json_error, parse_request_url, rule_kind_name},
    state::AppState,
};

pub(crate) async fn rewrite_url(
    State(state): State<AppState>,
    Query(query): Query<RewriteQuery>,
) -> Response {
    let original = match parse_request_url(&query.url) {
        Ok(url) => url,
        Err(response) => return response,
    };

    match state.rules.rewrite(&original) {
        Some(rewrite) => Json(RewriteResponse {
            original: original.to_string(),
            rewritten: rewrite.target.to_string(),
            kind: rule_kind_name(rewrite),
        })
        .into_response(),
        None => json_error(axum::http::StatusCode::NOT_FOUND, "no matching mirror rule"),
    }
}
