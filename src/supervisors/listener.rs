use std::net::SocketAddr;

use anyhow::Result;
use axum::{Router, serve};
use tokio::{net::TcpListener, sync::oneshot};

use crate::{
    gateway::transport::tls::{self, TlsInterceptService},
    socket::bind_dual_stack_tcp_listener,
    workers::Workers,
};

use super::ShutdownJoinHandle;

#[derive(Clone)]
pub struct ListenerSupervisor {
    workers: Workers,
}

pub type HttpListenerHandle = ShutdownJoinHandle;
pub type TlsListenerHandle = ShutdownJoinHandle;

impl ListenerSupervisor {
    pub fn new(workers: Workers) -> Self {
        Self { workers }
    }

    pub async fn start_http(
        &self,
        app: Router,
        listen_addr: SocketAddr,
    ) -> Result<HttpListenerHandle> {
        let listener = TcpListener::bind(listen_addr).await?;
        Ok(spawn_shutdownable_listener(
            &self.workers,
            "http-listener",
            move |shutdown_rx| async move {
                if let Err(error) = serve(listener, app)
                    .with_graceful_shutdown(async move {
                        let _ = shutdown_rx.await;
                    })
                    .await
                {
                    tracing::error!(?error, "HTTP listener worker exited unexpectedly");
                }
            },
        ))
    }

    pub fn start_tls(
        &self,
        app: Router,
        port: u16,
        tls_intercept: TlsInterceptService,
    ) -> Result<TlsListenerHandle> {
        let listener = bind_dual_stack_tcp_listener(port, 1024)?;
        Ok(spawn_shutdownable_listener(
            &self.workers,
            "tls-listener",
            move |shutdown_rx| async move {
                if let Err(error) =
                    tls::serve_app_tls_with_listener(tls_intercept, app, listener, shutdown_rx)
                        .await
                {
                    tracing::error!(?error, "TLS listener worker exited unexpectedly");
                }
            },
        ))
    }
}

fn spawn_shutdownable_listener<F, Fut>(
    workers: &Workers,
    worker_name: &'static str,
    task_factory: F,
) -> ShutdownJoinHandle
where
    F: FnOnce(oneshot::Receiver<()>) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let join = workers.spawn(worker_name, task_factory(shutdown_rx));
    ShutdownJoinHandle::new(shutdown_tx, join)
}
