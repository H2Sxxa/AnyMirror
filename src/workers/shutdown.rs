use tokio::{sync::oneshot, task::JoinHandle};

pub struct ShutdownJoinHandle {
    shutdown_tx: Option<oneshot::Sender<()>>,
    join: JoinHandle<()>,
}

impl ShutdownJoinHandle {
    pub fn new(shutdown_tx: oneshot::Sender<()>, join: JoinHandle<()>) -> Self {
        Self {
            shutdown_tx: Some(shutdown_tx),
            join,
        }
    }

    pub async fn shutdown(mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        let _ = self.join.await;
    }
}
