use std::sync::Arc;

use anyhow::Result;
use axum::{serve, Router};
use tokio::net::TcpListener;
use tokio::spawn;

use crate::config::AppConfig;
use crate::socket::bind_dual_stack_tcp_listener;
use crate::traffic::shared::FakeDnsServer;
use crate::traffic::windivert::run_transparent_windivert_runtimes;

use super::{
    executor::HyperExecutor,
    handlers::{proxy_entry::proxy_entry, transparent::transparent_entry},
    responses::shutdown_signal,
    router::build_common_router,
    state::AppState,
    tls,
};

pub async fn serve_explicit(config: AppConfig) -> Result<()> {
    let state = build_state(config)?;
    let listen_addr = state.listen_addr;
    let app = build_common_router::<HyperExecutor>()
        .fallback(proxy_entry)
        .with_state(state);
    let listener = TcpListener::bind(listen_addr).await?;
    serve_app_with_listener(app, listener).await
}

pub async fn serve_transparent(config: AppConfig) -> Result<()> {
    let fake_dns_server = FakeDnsServer::start(config.backend.dns.clone(), &config.rules).await?;
    let state = build_state(config.clone())?;
    let proxy_redirect_addr = state.listen_addr;
    let http_listener = bind_dual_stack_tcp_listener(proxy_redirect_addr.port(), 1024)?;
    let app = build_common_router::<HyperExecutor>()
        .fallback(transparent_entry)
        .with_state(state.clone());

    run_transparent_windivert_runtimes(&config, fake_dns_server, proxy_redirect_addr)?;

    let tls_port = config
        .tls_port
        .unwrap_or_else(|| proxy_redirect_addr.port() + 1);
    let tls_listener = bind_dual_stack_tcp_listener(tls_port, 1024)?;

    let app_for_tls = app.clone();
    spawn(async move {
        let _ = tls::serve_app_tls_with_listener(app_for_tls, tls_listener).await;
    });

    serve_app_with_listener(app, http_listener).await
}

fn build_state(config: AppConfig) -> Result<AppState<HyperExecutor>> {
    let executor = HyperExecutor::new()?;

    Ok(AppState {
        executor,
        listen_addr: config.listen_addr,
        rules: Arc::new(config.rules),
    })
}

async fn serve_app_with_listener(app: Router, listener: TcpListener) -> Result<()> {
    serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}
