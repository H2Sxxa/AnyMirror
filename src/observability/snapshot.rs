use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct RuntimeSnapshot {
    pub listen_addr: Option<SocketAddr>,
    pub tls_listen_addr: Option<SocketAddr>,
    pub fake_dns_listen_addr: Option<SocketAddr>,
    pub active_rule_count: usize,
    pub active_plugin_count: usize,
    pub reload_generation: u64,
}

#[derive(Debug, Clone)]
pub struct RuntimeSnapshotStore {
    inner: Arc<Mutex<RuntimeSnapshot>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeSnapshotStoreError {
    LockPoisoned,
}

impl RuntimeSnapshotStore {
    pub fn new(initial: RuntimeSnapshot) -> Self {
        Self {
            inner: Arc::new(Mutex::new(initial)),
        }
    }

    pub fn replace(&self, next: RuntimeSnapshot) -> Result<(), RuntimeSnapshotStoreError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| RuntimeSnapshotStoreError::LockPoisoned)?;
        *inner = next;
        Ok(())
    }

    pub fn snapshot(&self) -> Result<RuntimeSnapshot, RuntimeSnapshotStoreError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| RuntimeSnapshotStoreError::LockPoisoned)?;
        Ok(inner.clone())
    }
}

impl Display for RuntimeSnapshotStoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LockPoisoned => f.write_str("runtime snapshot store lock poisoned"),
        }
    }
}

impl Error for RuntimeSnapshotStoreError {}
