use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use super::types::{WorkerKind, WorkerSnapshot, WorkerState};

#[derive(Debug, Clone, Default)]
pub struct Workers {
    inner: Arc<Mutex<HashMap<String, WorkerSnapshot>>>,
}

impl Workers {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn running_count(&self) -> usize {
        let Ok(registry) = self.inner.lock() else {
            return 0;
        };

        registry
            .values()
            .filter(|snapshot| matches!(snapshot.state, WorkerState::Running))
            .count()
    }

    pub(super) fn mark_running(&self, name: &str, kind: WorkerKind) {
        let Ok(mut registry) = self.inner.lock() else {
            return;
        };

        registry.insert(
            name.to_string(),
            WorkerSnapshot {
                kind,
                state: WorkerState::Running,
                started_at: Instant::now(),
            },
        );
    }

    pub(super) fn mark_finished(
        &self,
        name: &str,
        state: WorkerState,
    ) -> Option<(WorkerKind, Duration)> {
        let Ok(mut registry) = self.inner.lock() else {
            return None;
        };

        let snapshot = registry.get_mut(name)?;
        snapshot.state = state;
        Some((snapshot.kind, snapshot.started_at.elapsed()))
    }
}
