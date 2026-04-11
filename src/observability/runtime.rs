use crate::config::ObservabilityOptions;

use super::{ObservabilityEvent, RecentEventStore, RuntimeSnapshot, RuntimeSnapshotStore};

const DEFAULT_RECENT_EVENT_CAPACITY: usize = 512;

#[derive(Debug, Clone)]
pub struct ObservabilityRuntime {
    events: Option<RecentEventStore>,
    snapshots: Option<RuntimeSnapshotStore>,
}

impl ObservabilityRuntime {
    pub fn new(config: &ObservabilityOptions) -> Self {
        if !config.enabled {
            return Self {
                events: None,
                snapshots: None,
            };
        }

        Self {
            events: Some(RecentEventStore::new(DEFAULT_RECENT_EVENT_CAPACITY)),
            snapshots: Some(RuntimeSnapshotStore::new(RuntimeSnapshot::default())),
        }
    }

    pub fn enabled(&self) -> bool {
        self.events.is_some() || self.snapshots.is_some()
    }

    pub fn record_event<F>(&self, build_event: F)
    where
        F: FnOnce() -> ObservabilityEvent,
    {
        let Some(store) = self.events.as_ref() else {
            return;
        };

        let _ = store.record(build_event());
    }

    pub fn replace_snapshot<F>(&self, build_snapshot: F)
    where
        F: FnOnce() -> RuntimeSnapshot,
    {
        let Some(store) = self.snapshots.as_ref() else {
            return;
        };

        let _ = store.replace(build_snapshot());
    }

    pub fn snapshot(&self) -> Option<RuntimeSnapshot> {
        self.snapshots
            .as_ref()
            .and_then(|store| store.snapshot().ok())
    }

    pub fn recent_events(&self) -> Option<Vec<ObservabilityEvent>> {
        self.events.as_ref().and_then(|store| store.snapshot().ok())
    }
}
