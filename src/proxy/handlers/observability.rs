use axum::{Json, extract::State, response::IntoResponse};
use serde::Serialize;

use super::super::{executors::UpstreamExecutor, state::AppState};
use crate::observability::{ObservabilityEvent, RuntimeSnapshot};

#[derive(Debug, Serialize)]
struct RuntimeStateResponse {
    enabled: bool,
    snapshot: Option<RuntimeSnapshot>,
}

#[derive(Debug, Serialize)]
struct RecentEventsResponse {
    enabled: bool,
    events: Vec<ObservabilityEvent>,
}

pub(crate) async fn runtime_state<E: UpstreamExecutor>(
    State(state): State<AppState<E>>,
) -> impl IntoResponse {
    Json(RuntimeStateResponse {
        enabled: state.observability.enabled(),
        snapshot: state.observability.snapshot(),
    })
}

pub(crate) async fn recent_events<E: UpstreamExecutor>(
    State(state): State<AppState<E>>,
) -> impl IntoResponse {
    Json(RecentEventsResponse {
        enabled: state.observability.enabled(),
        events: state.observability.recent_events().unwrap_or_default(),
    })
}
