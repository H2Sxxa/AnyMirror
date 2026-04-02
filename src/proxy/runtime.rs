use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::Router;

use crate::config::AppConfig;
use crate::traffic::windivert::{run_transparent_windivert_runtimes, WinDivertLayer};

use super::{
    executor::HyperExecutor,
    handlers::{proxy_entry::proxy_entry, transparent::transparent_entry},
    responses::shutdown_signal,
    router::build_common_router,
    state::AppState,
    tls,
};

pub async fn serve_explicit(config: AppConfig) -> anyhow::Result<()> {
    let state = build_state(config)?;
    let listen_addr = state.listen_addr;
    let app = build_common_router::<HyperExecutor>()
        .fallback(proxy_entry)
        .with_state(state);
    serve_app(app, listen_addr).await
}

pub async fn serve_transparent(config: AppConfig, layer: WinDivertLayer) -> anyhow::Result<()> {
    let state = build_state(config.clone())?;
    let mut listen_addr = state.listen_addr;
    let proxy_redirect_addr = listen_addr;
    listen_addr.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let app = build_common_router::<HyperExecutor>()
        .fallback(transparent_entry)
        .with_state(state.clone());

    run_transparent_windivert_runtimes(&config, proxy_redirect_addr, layer)?;

    let mut https_listen_addr = listen_addr;
    let tls_port = config.tls_port.unwrap_or_else(|| listen_addr.port() + 1);
    https_listen_addr.set_port(tls_port);

    let app_for_tls = app.clone();
    tokio::spawn(async move {
        let _ = tls::serve_app_tls(app_for_tls, https_listen_addr).await;
    });

    serve_app(app, listen_addr).await
}

fn build_state(config: AppConfig) -> anyhow::Result<AppState<HyperExecutor>> {
    let executor = HyperExecutor::new()?;

    Ok(AppState {
        executor,
        listen_addr: config.listen_addr,
        rules: Arc::new(config.rules),
    })
}

async fn serve_app(app: Router, listen_addr: SocketAddr) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}
