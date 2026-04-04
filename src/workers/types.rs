use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerKind {
    Async,
    Blocking,
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
