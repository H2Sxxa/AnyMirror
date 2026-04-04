use std::path::PathBuf;

use anyhow::Result;
use axum::{serve, Router};
use tokio::net::TcpListener;

use crate::config::AppConfig;
use crate::rules::pool::LiveRules;
use crate::socket::bind_dual_stack_tcp_listener;
use crate::traffic::shared::FakeDnsServer;
use crate::traffic::windivert::run_transparent_windivert_runtimes;
use crate::watch::spawn_config_watch;
use crate::workers::Workers;

use super::{
    executor::HyperExecutor,
    handlers::{proxy_entry::proxy_entry, transparent::transparent_entry},
    responses::shutdown_signal,
    router::build_common_router,
    state::AppState,
    tls,
};

pub async fn serve_explicit(
    config: AppConfig,
    watch_config_path: Option<PathBuf>,
    workers: Workers,
) -> Result<()> {
    let live_rules = LiveRules::new(config.rules.clone());
    maybe_spawn_config_watch(
        watch_config_path,
        &config,
        live_rules.clone(),
        workers.clone(),
    );
    let state = build_state(config.listen_addr, live_rules)?;
    let listen_addr = state.listen_addr;
    let app = build_common_router::<HyperExecutor>()
        .fallback(proxy_entry)
        .with_state(state);
    let listener = TcpListener::bind(listen_addr).await?;
    serve_app_with_listener(app, listener).await
}

pub async fn serve_transparent(
    config: AppConfig,
    watch_config_path: Option<PathBuf>,
    workers: Workers,
) -> Result<()> {
    let live_rules = LiveRules::new(config.rules.clone());
    maybe_spawn_config_watch(
        watch_config_path,
        &config,
        live_rules.clone(),
        workers.clone(),
    );
    let fake_dns_server = FakeDnsServer::start(
        config.backend.dns.clone(),
        live_rules.clone(),
        workers.clone(),
    )
    .await?;
    let state = build_state(config.listen_addr, live_rules)?;
    let proxy_redirect_addr = state.listen_addr;
    let http_listener = bind_dual_stack_tcp_listener(proxy_redirect_addr.port(), 1024)?;
    let app = build_common_router::<HyperExecutor>()
        .fallback(transparent_entry)
        .with_state(state.clone());

    run_transparent_windivert_runtimes(
        &config,
        fake_dns_server,
        proxy_redirect_addr,
        workers.clone(),
    )?;

    let tls_port = config
        .tls_port
        .unwrap_or_else(|| proxy_redirect_addr.port() + 1);
    let tls_listener = bind_dual_stack_tcp_listener(tls_port, 1024)?;

    let app_for_tls = app.clone();
    workers.spawn("tls-listener", async move {
        if let Err(error) = tls::serve_app_tls_with_listener(app_for_tls, tls_listener).await {
            tracing::error!(?error, "TLS listener worker exited unexpectedly");
        }
    });

    serve_app_with_listener(app, http_listener).await
}

fn build_state(
    listen_addr: std::net::SocketAddr,
    rules: LiveRules,
) -> Result<AppState<HyperExecutor>> {
    let executor = HyperExecutor::new()?;

    Ok(AppState {
        executor,
        listen_addr,
        rules,
    })
}

fn maybe_spawn_config_watch(
    watch_config_path: Option<PathBuf>,
    config: &AppConfig,
    live_rules: LiveRules,
    workers: Workers,
) {
    if let Some(path) = watch_config_path {
        spawn_config_watch(path, config, live_rules, workers);
    }
}

async fn serve_app_with_listener(app: Router, listener: TcpListener) -> Result<()> {
    serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}
