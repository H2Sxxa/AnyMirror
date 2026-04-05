use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerKind {
    Async,
    Blocking,
}

impl WorkerKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Async => "async",
            Self::Blocking => "blocking",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState {
    Running,
    Finished,
    Panicked,
}

#[derive(Debug, Clone)]
pub struct WorkerSnapshot {
    pub kind: WorkerKind,
    pub state: WorkerState,
    pub started_at: Instant,
}
