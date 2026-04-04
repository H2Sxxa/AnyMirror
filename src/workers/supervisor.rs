use std::future::Future;

use tokio::{spawn, task::JoinHandle, task::spawn_blocking};

use super::{
    registry::Workers,
    types::{WorkerKind, WorkerState},
};

impl Workers {
    pub fn spawn<F>(&self, name: impl Into<String>, future: F) -> JoinHandle<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let name = name.into();
        self.mark_running(&name, WorkerKind::Async);
        tracing::info!(
            worker_name = %name,
            worker_kind = "async",
            active_workers = self.running_count(),
            "Worker started"
        );

        let workers = self.clone();
        spawn(async move {
            let join = spawn(future);
            match join.await {
                Ok(()) => {
                    let (_, runtime) = workers
                        .mark_finished(&name, WorkerState::Finished)
                        .unwrap_or((WorkerKind::Async, Default::default()));
                    tracing::info!(
                        worker_name = %name,
                        worker_kind = "async",
                        active_workers = workers.running_count(),
                        runtime_ms = runtime.as_millis(),
                        "Worker finished"
                    );
                }
                Err(error) => {
                    let (_, runtime) = workers
                        .mark_finished(&name, WorkerState::Panicked)
                        .unwrap_or((WorkerKind::Async, Default::default()));
                    tracing::error!(
                        worker_name = %name,
                        worker_kind = "async",
                        active_workers = workers.running_count(),
                        runtime_ms = runtime.as_millis(),
                        ?error,
                        "Worker panicked"
                    );
                }
            }
        })
    }

    pub fn spawn_blocking<F>(&self, name: impl Into<String>, work: F) -> JoinHandle<()>
    where
        F: FnOnce() + Send + 'static,
    {
        let name = name.into();
        self.mark_running(&name, WorkerKind::Blocking);
        tracing::info!(
            worker_name = %name,
            worker_kind = "blocking",
            active_workers = self.running_count(),
            "Worker started"
        );

        let workers = self.clone();
        spawn(async move {
            let join = spawn_blocking(work);
            match join.await {
                Ok(()) => {
                    let (_, runtime) = workers
                        .mark_finished(&name, WorkerState::Finished)
                        .unwrap_or((WorkerKind::Blocking, Default::default()));
                    tracing::info!(
                        worker_name = %name,
                        worker_kind = "blocking",
                        active_workers = workers.running_count(),
                        runtime_ms = runtime.as_millis(),
                        "Worker finished"
                    );
                }
                Err(error) => {
                    let (_, runtime) = workers
                        .mark_finished(&name, WorkerState::Panicked)
                        .unwrap_or((WorkerKind::Blocking, Default::default()));
                    tracing::error!(
                        worker_name = %name,
                        worker_kind = "blocking",
                        active_workers = workers.running_count(),
                        runtime_ms = runtime.as_millis(),
                        ?error,
                        "Worker panicked"
                    );
                }
            }
        })
    }
}
