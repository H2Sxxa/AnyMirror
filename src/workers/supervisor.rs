use std::future::Future;

use tokio::{
    spawn,
    task::{JoinError, JoinHandle, spawn_blocking},
};

use super::{
    registry::Workers,
    types::{WorkerKind, WorkerState},
};

pub struct ExternalWorkerGuard {
    workers: Workers,
    name: String,
    kind: WorkerKind,
}

impl Workers {
    pub fn spawn<F>(&self, name: impl Into<String>, future: F) -> JoinHandle<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.spawn_tracked_worker(name, WorkerKind::Async, move || spawn(future))
    }

    pub fn spawn_blocking<F>(&self, name: impl Into<String>, work: F) -> JoinHandle<()>
    where
        F: FnOnce() + Send + 'static,
    {
        self.spawn_tracked_worker(name, WorkerKind::Blocking, move || spawn_blocking(work))
    }

    pub fn track_external_thread(&self, name: impl Into<String>) -> ExternalWorkerGuard {
        self.track_external_worker(name, WorkerKind::Blocking)
    }

    pub fn track_external_worker(
        &self,
        name: impl Into<String>,
        kind: WorkerKind,
    ) -> ExternalWorkerGuard {
        let name = name.into();
        self.mark_running(&name, kind);
        log_worker_started(self, &name, kind);

        ExternalWorkerGuard {
            workers: self.clone(),
            name,
            kind,
        }
    }

    fn spawn_tracked_worker<F>(
        &self,
        name: impl Into<String>,
        kind: WorkerKind,
        spawn_task: F,
    ) -> JoinHandle<()>
    where
        F: FnOnce() -> JoinHandle<()> + Send + 'static,
    {
        let name = name.into();
        self.mark_running(&name, kind);
        log_worker_started(self, &name, kind);

        let workers = self.clone();
        spawn(async move {
            let join = spawn_task();
            log_worker_completion(&workers, &name, kind, join.await);
        })
    }
}

impl Drop for ExternalWorkerGuard {
    fn drop(&mut self) {
        let state = if std::thread::panicking() {
            WorkerState::Panicked
        } else {
            WorkerState::Finished
        };
        log_external_worker_completion(&self.workers, &self.name, self.kind, state);
    }
}

fn log_worker_started(workers: &Workers, name: &str, kind: WorkerKind) {
    tracing::info!(
        worker_name = %name,
        worker_kind = kind.label(),
        active_workers = workers.running_count(),
        "Worker started"
    );
}

fn log_worker_completion(
    workers: &Workers,
    name: &str,
    kind: WorkerKind,
    result: Result<(), JoinError>,
) {
    match result {
        Ok(()) => {
            let (_, runtime) = workers
                .mark_finished(name, WorkerState::Finished)
                .unwrap_or((kind, Default::default()));
            tracing::info!(
                worker_name = %name,
                worker_kind = kind.label(),
                active_workers = workers.running_count(),
                runtime_ms = runtime.as_millis(),
                "Worker finished"
            );
        }
        Err(error) => {
            let (_, runtime) = workers
                .mark_finished(name, WorkerState::Panicked)
                .unwrap_or((kind, Default::default()));
            tracing::error!(
                worker_name = %name,
                worker_kind = kind.label(),
                active_workers = workers.running_count(),
                runtime_ms = runtime.as_millis(),
                ?error,
                "Worker panicked"
            );
        }
    }
}

fn log_external_worker_completion(
    workers: &Workers,
    name: &str,
    kind: WorkerKind,
    state: WorkerState,
) {
    let (_, runtime) = workers
        .mark_finished(name, state)
        .unwrap_or((kind, Default::default()));

    match state {
        WorkerState::Finished => {
            tracing::info!(
                worker_name = %name,
                worker_kind = kind.label(),
                active_workers = workers.running_count(),
                runtime_ms = runtime.as_millis(),
                "Worker finished"
            );
        }
        WorkerState::Panicked => {
            tracing::error!(
                worker_name = %name,
                worker_kind = kind.label(),
                active_workers = workers.running_count(),
                runtime_ms = runtime.as_millis(),
                "Worker panicked"
            );
        }
        WorkerState::Running => {}
    }
}
