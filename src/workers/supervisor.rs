use std::future::Future;

use tokio::{
    spawn,
    task::{JoinError, JoinHandle, spawn_blocking},
};

use super::{
    registry::Workers,
    types::{WorkerKind, WorkerState},
};

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
