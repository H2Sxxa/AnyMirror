use std::collections::VecDeque;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservabilityEventLevel {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservabilityEvent {
    pub timestamp: SystemTime,
    pub level: ObservabilityEventLevel,
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct RecentEventStore {
    capacity: usize,
    inner: Arc<Mutex<VecDeque<ObservabilityEvent>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecentEventStoreError {
    LockPoisoned,
}

impl RecentEventStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
        }
    }

    pub fn record(&self, event: ObservabilityEvent) -> Result<(), RecentEventStoreError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| RecentEventStoreError::LockPoisoned)?;

        inner.push_back(event);
        while inner.len() > self.capacity {
            inner.pop_front();
        }

        Ok(())
    }

    pub fn snapshot(&self) -> Result<Vec<ObservabilityEvent>, RecentEventStoreError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| RecentEventStoreError::LockPoisoned)?;

        Ok(inner.iter().cloned().collect())
    }
}

impl ObservabilityEvent {
    pub fn new(
        level: ObservabilityEventLevel,
        kind: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: SystemTime::now(),
            level,
            kind: kind.into(),
            message: message.into(),
        }
    }
}

impl Display for RecentEventStoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LockPoisoned => f.write_str("recent event store lock poisoned"),
        }
    }
}

impl Error for RecentEventStoreError {}
