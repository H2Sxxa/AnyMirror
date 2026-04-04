use std::path::PathBuf;

use anyhow::Result;
use axum::Router;
use tokio::sync::mpsc;

use crate::config::AppConfig;
use crate::rules::pool::LiveRules;
use crate::supervisors::{
    FakeDnsInstance, FakeDnsSupervisor, HttpListenerHandle, InterceptBackendHandle,
    InterceptBackendRuntimeConfig, InterceptBackendSupervisor, ListenerSupervisor,
    TlsListenerHandle,
};
use crate::watch::spawn_config_watch;
use crate::workers::Workers;

use super::{
    executor::HyperExecutor,
    handlers::{proxy_entry::proxy_entry, transparent::transparent_entry},
    responses::shutdown_signal,
    router::build_common_router,
    state::AppState,
};

pub async fn serve_explicit(
    config: AppConfig,
    watch_config_path: Option<PathBuf>,
    workers: Workers,
) -> Result<()> {
    let live_rules = LiveRules::new(config.rules.clone());
    let listener_supervisor = ListenerSupervisor::new(workers.clone());
    let (reload_tx, mut reload_rx) = mpsc::unbounded_channel();

    maybe_spawn_config_watch(
        watch_config_path,
        &config,
        live_rules.clone(),
        workers,
        Some(reload_tx),
    );

    let state = build_state(config.listen_addr, live_rules)?;
    let app = build_common_router::<HyperExecutor>()
        .fallback(proxy_entry)
        .with_state(state);
    let mut http_handle = listener_supervisor
        .start_http(app.clone(), config.listen_addr)
        .await?;
    let mut active_config = config;

    loop {
        tokio::select! {
            _ = shutdown_signal() => {
                http_handle.shutdown().await;
                return Ok(());
            }
            maybe_config = reload_rx.recv() => {
                let Some(reloaded_config) = maybe_config else {
                    continue;
                };
                if reloaded_config.listen_addr != active_config.listen_addr {
                    http_handle.shutdown().await;
                    http_handle = listener_supervisor
                        .start_http(app.clone(), reloaded_config.listen_addr)
                        .await?;
                }
                active_config = reloaded_config;
            }
        }
    }
}

pub async fn serve_transparent(
    config: AppConfig,
    watch_config_path: Option<PathBuf>,
    workers: Workers,
) -> Result<()> {
    let live_rules = LiveRules::new(config.rules.clone());
    let listener_supervisor = ListenerSupervisor::new(workers.clone());
    let fake_dns_supervisor = FakeDnsSupervisor::new(workers.clone());
    let intercept_supervisor = InterceptBackendSupervisor::new(workers.clone());
    let (reload_tx, mut reload_rx) = mpsc::unbounded_channel();

    maybe_spawn_config_watch(
        watch_config_path,
        &config,
        live_rules.clone(),
        workers,
        Some(reload_tx),
    );

    let state = build_state(config.listen_addr, live_rules.clone())?;
    let app = build_common_router::<HyperExecutor>()
        .fallback(transparent_entry)
        .with_state(state.clone());

    let mut runtime = start_transparent_components(
        &listener_supervisor,
        &fake_dns_supervisor,
        &intercept_supervisor,
        app.clone(),
        &config,
        live_rules,
    )
    .await?;

    loop {
        tokio::select! {
            _ = shutdown_signal() => {
                runtime.shutdown().await;
                return Ok(());
            }
            maybe_config = reload_rx.recv() => {
                let Some(reloaded_config) = maybe_config else {
                    continue;
                };
                runtime.reload(
                    &listener_supervisor,
                    &fake_dns_supervisor,
                    &intercept_supervisor,
                    app.clone(),
                    &reloaded_config,
                    state.rules.clone(),
                ).await?;
            }
        }
    }
}

fn build_state(
    _listen_addr: std::net::SocketAddr,
    rules: LiveRules,
) -> Result<AppState<HyperExecutor>> {
    let executor = HyperExecutor::new()?;

    Ok(AppState { executor, rules })
}

fn maybe_spawn_config_watch(
    watch_config_path: Option<PathBuf>,
    config: &AppConfig,
    live_rules: LiveRules,
    workers: Workers,
    reload_tx: Option<mpsc::UnboundedSender<AppConfig>>,
) {
    if let Some(path) = watch_config_path {
        spawn_config_watch(path, config, live_rules, workers, reload_tx);
    }
}

struct TransparentRuntimeHandles {
    config: AppConfig,
    http: Option<HttpListenerHandle>,
    tls: Option<TlsListenerHandle>,
    dns: Option<FakeDnsInstance>,
    intercept: Option<InterceptBackendHandle>,
}

impl TransparentRuntimeHandles {
    async fn shutdown(mut self) {
        if let Some(http) = self.http.take() {
            http.shutdown().await;
        }
        if let Some(tls) = self.tls.take() {
            tls.shutdown().await;
        }
        if let Some(dns) = self.dns.take() {
            dns.shutdown().await;
        }
        if let Some(intercept) = self.intercept.take() {
            intercept.shutdown().await;
        }
    }

    async fn reload(
        &mut self,
        listener_supervisor: &ListenerSupervisor,
        fake_dns_supervisor: &FakeDnsSupervisor,
        intercept_supervisor: &InterceptBackendSupervisor,
        app: Router,
        next_config: &AppConfig,
        live_rules: LiveRules,
    ) -> Result<()> {
        let reload_plan = TransparentReloadPlan::from_configs(&self.config, next_config);

        if reload_plan.restart_intercept {
            if let Some(intercept) = self.intercept.take() {
                intercept.shutdown().await;
            }
        }

        if reload_plan.restart_dns {
            if let Some(dns) = self.dns.take() {
                dns.shutdown().await;
            }
            self.dns = Some(
                fake_dns_supervisor
                    .start(next_config.backend.dns.clone(), live_rules.clone())
                    .await?,
            );
        }

        if reload_plan.restart_http {
            if let Some(http) = self.http.take() {
                http.shutdown().await;
            }
            self.http = Some(
                listener_supervisor
                    .start_http(app.clone(), next_config.listen_addr)
                    .await?,
            );
        }

        if reload_plan.restart_tls {
            if let Some(tls) = self.tls.take() {
                tls.shutdown().await;
            }
            self.tls =
                Some(listener_supervisor.start_tls(app.clone(), effective_tls_port(next_config))?);
        }

        if reload_plan.restart_intercept {
            self.intercept = Some(
                intercept_supervisor
                    .start(InterceptBackendRuntimeConfig {
                        listen_addr: next_config.listen_addr,
                        tls_port: next_config.tls_port,
                        backend: next_config.backend.clone(),
                        fake_dns_server: self
                            .dns
                            .as_ref()
                            .expect("dns instance should exist")
                            .server
                            .clone(),
                    })
                    .await?,
            );
        }

        self.config = next_config.clone();
        Ok(())
    }
}

async fn start_transparent_components(
    listener_supervisor: &ListenerSupervisor,
    fake_dns_supervisor: &FakeDnsSupervisor,
    intercept_supervisor: &InterceptBackendSupervisor,
    app: Router,
    config: &AppConfig,
    live_rules: LiveRules,
) -> Result<TransparentRuntimeHandles> {
    let dns = fake_dns_supervisor
        .start(config.backend.dns.clone(), live_rules)
        .await?;
    let http = listener_supervisor
        .start_http(app.clone(), config.listen_addr)
        .await?;
    let tls_port = effective_tls_port(config);
    let tls = listener_supervisor.start_tls(app, tls_port)?;
    let intercept = intercept_supervisor
        .start(InterceptBackendRuntimeConfig {
            listen_addr: config.listen_addr,
            tls_port: config.tls_port,
            backend: config.backend.clone(),
            fake_dns_server: dns.server.clone(),
        })
        .await?;

    Ok(TransparentRuntimeHandles {
        config: config.clone(),
        http: Some(http),
        tls: Some(tls),
        dns: Some(dns),
        intercept: Some(intercept),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransparentReloadPlan {
    restart_http: bool,
    restart_tls: bool,
    restart_dns: bool,
    restart_intercept: bool,
}

impl TransparentReloadPlan {
    fn from_configs(current: &AppConfig, next: &AppConfig) -> Self {
        let restart_http = current.listen_addr != next.listen_addr;
        let current_tls_port = effective_tls_port(current);
        let next_tls_port = effective_tls_port(next);
        let restart_tls = current_tls_port != next_tls_port;
        let restart_dns = current.backend.dns != next.backend.dns;
        let restart_intercept = restart_dns
            || current.backend.windivert != next.backend.windivert
            || current.listen_addr != next.listen_addr
            || current_tls_port != next_tls_port;

        Self {
            restart_http,
            restart_tls,
            restart_dns,
            restart_intercept,
        }
    }
}

fn effective_tls_port(config: &AppConfig) -> u16 {
    config
        .tls_port
        .unwrap_or_else(|| config.listen_addr.port() + 1)
}
