use std::path::PathBuf;

use anyhow::{Context, Result};
use axum::Router;
use tokio::sync::mpsc;

use crate::config::AppConfig;
use crate::config::{BackendOptions, TransparentBackendKind, TunStack};
use crate::observability::{
    ObservabilityEvent, ObservabilityEventLevel, ObservabilityRuntime, RuntimeSnapshot,
};
use crate::plugins::LivePluginRegistry;
use crate::rules::pool::LiveRuleSet;
use crate::supervisors::{
    FakeDnsInstance, FakeDnsSupervisor, HttpListenerHandle, InterceptBackendHandle,
    InterceptBackendRuntimeConfig, InterceptBackendSupervisor, ListenerSupervisor,
    PluginSupervisor, TlsListenerHandle,
};
use crate::watch::{ConfigReloadRequest, spawn_config_watch};
use crate::workers::{ShutdownJoinHandle, Workers};

use super::{
    handlers::{proxy_entry::proxy_entry, transparent::transparent_entry},
    http::responses::shutdown_signal,
    routers::build_common_router,
    state::AppState,
    transport::tls::TlsInterceptService,
    upstream::executors::HyperExecutor,
};

pub async fn serve_explicit(
    config: AppConfig,
    watch_config_path: Option<PathBuf>,
    workers: Workers,
) -> Result<()> {
    let live_rules = LiveRuleSet::new(config.rules.clone());
    let plugin_supervisor = PluginSupervisor::new(workers.clone());
    let live_plugins = plugin_supervisor
        .start(&config.plugins, live_rules.clone())
        .await
        .context("failed to initialize plugin registry")?;
    let listener_supervisor = ListenerSupervisor::new(workers.clone());
    let (reload_tx, mut reload_rx) = mpsc::unbounded_channel();

    let state = build_state(&config, live_rules.clone(), live_plugins.clone())?;
    let app = build_common_router::<HyperExecutor>()
        .fallback(proxy_entry)
        .with_state(state.clone());
    let mut http_handle = listener_supervisor
        .start_http(app.clone(), config.listen_addr)
        .await?;
    let mut config_watch = maybe_spawn_config_watch(
        watch_config_path,
        live_rules.clone(),
        state.observability.clone(),
        &config,
        workers.clone(),
        Some(reload_tx),
    );
    let mut active_config = config;
    let mut active_generation: u64 = 0;
    update_explicit_snapshot(
        &state.observability,
        &active_config,
        &state,
        active_generation,
    );
    state.observability.record_event(|| {
        ObservabilityEvent::new(
            ObservabilityEventLevel::Info,
            "runtime.explicit_started",
            format!("Explicit proxy listening on {}", active_config.listen_addr),
        )
    });

    loop {
        tokio::select! {
            _ = shutdown_signal() => {
                if let Some(watch) = config_watch.take() {
                    watch.shutdown().await;
                }
                http_handle.shutdown().await;
                state.observability.record_event(|| {
                    ObservabilityEvent::new(
                        ObservabilityEventLevel::Info,
                        "runtime.explicit_stopped",
                        format!("Explicit proxy stopped on {}", active_config.listen_addr),
                    )
                });
                return Ok(());
            }
            maybe_config = reload_rx.recv() => {
                let Some(reload_request) = maybe_config else {
                    continue;
                };
                let (reload_request, skipped_generations) =
                    take_latest_reload_request(reload_request, &mut reload_rx);
                if skipped_generations > 0 {
                    tracing::info!(
                        applied_generation = reload_request.generation,
                        skipped_generations,
                        "Coalesced explicit-mode runtime reload requests"
                    );
                }
                if reload_request.generation <= active_generation {
                    tracing::debug!(
                        active_generation,
                        discarded_generation = reload_request.generation,
                        "Discarded stale explicit-mode runtime reload generation"
                    );
                    continue;
                }
                let ConfigReloadRequest {
                    generation,
                    config: reloaded_config,
                } = reload_request;
                plugin_supervisor
                    .reload(&state.plugins, &reloaded_config.plugins, state.rules.clone())
                    .await
                    .context("failed to rebuild plugin registry during explicit reload")?;
                if reloaded_config.listen_addr != active_config.listen_addr {
                    http_handle.shutdown().await;
                    http_handle = listener_supervisor
                        .start_http(app.clone(), reloaded_config.listen_addr)
                        .await?;
                }
                active_generation = generation;
                active_config = reloaded_config;
                update_explicit_snapshot(&state.observability, &active_config, &state, active_generation);
                state.observability.record_event(|| {
                    ObservabilityEvent::new(
                        ObservabilityEventLevel::Info,
                        "runtime.explicit_reloaded",
                        format!(
                            "Applied explicit runtime reload generation {} on {}",
                            active_generation,
                            active_config.listen_addr
                        ),
                    )
                });
            }
        }
    }
}

pub async fn serve_transparent(
    config: AppConfig,
    watch_config_path: Option<PathBuf>,
    workers: Workers,
) -> Result<()> {
    let live_rules = LiveRuleSet::new(config.rules.clone());
    let plugin_supervisor = PluginSupervisor::new(workers.clone());
    let live_plugins = plugin_supervisor
        .start(&config.plugins, live_rules.clone())
        .await
        .context("failed to initialize plugin registry")?;
    let listener_supervisor = ListenerSupervisor::new(workers.clone());
    let fake_dns_supervisor = FakeDnsSupervisor::new(workers.clone());
    let intercept_supervisor = InterceptBackendSupervisor::new(workers.clone());
    let (reload_tx, mut reload_rx) = mpsc::unbounded_channel();

    let state = build_state(&config, live_rules.clone(), live_plugins.clone())?;
    let app = build_common_router::<HyperExecutor>()
        .fallback(transparent_entry)
        .with_state(state.clone());

    let mut runtime = start_transparent_components(
        &listener_supervisor,
        &fake_dns_supervisor,
        &intercept_supervisor,
        app.clone(),
        state.tls_intercept.clone(),
        &config,
        live_rules,
    )
    .await?;
    let mut config_watch = maybe_spawn_config_watch(
        watch_config_path,
        state.rules.clone(),
        state.observability.clone(),
        &config,
        workers.clone(),
        Some(reload_tx),
    );
    let mut active_generation: u64 = 0;
    let mut active_config = config;
    update_transparent_snapshot(
        &state.observability,
        &active_config,
        &state,
        active_generation,
    );
    state.observability.record_event(|| {
        ObservabilityEvent::new(
            ObservabilityEventLevel::Info,
            "runtime.transparent_started",
            format!(
                "Transparent proxy listening on {}",
                active_config.listen_addr
            ),
        )
    });

    loop {
        tokio::select! {
            _ = shutdown_signal() => {
                if let Some(watch) = config_watch.take() {
                    watch.shutdown().await;
                }
                runtime.shutdown().await;
                state.observability.record_event(|| {
                    ObservabilityEvent::new(
                        ObservabilityEventLevel::Info,
                        "runtime.transparent_stopped",
                        format!("Transparent proxy stopped on {}", active_config.listen_addr),
                    )
                });
                return Ok(());
            }
            maybe_config = reload_rx.recv() => {
                let Some(reload_request) = maybe_config else {
                    continue;
                };
                let (reload_request, skipped_generations) =
                    take_latest_reload_request(reload_request, &mut reload_rx);
                if skipped_generations > 0 {
                    tracing::info!(
                        applied_generation = reload_request.generation,
                        skipped_generations,
                        "Coalesced transparent-mode runtime reload requests"
                    );
                }
                if reload_request.generation <= active_generation {
                    tracing::debug!(
                        active_generation,
                        discarded_generation = reload_request.generation,
                        "Discarded stale transparent-mode runtime reload generation"
                    );
                    continue;
                }
                let ConfigReloadRequest {
                    generation,
                    config: reloaded_config,
                } = reload_request;
                plugin_supervisor
                    .reload(&state.plugins, &reloaded_config.plugins, state.rules.clone())
                    .await
                    .context("failed to rebuild plugin registry during transparent reload")?;
                tracing::info!(generation, "Applying transparent runtime reload generation");
                runtime.reload(
                    &listener_supervisor,
                    &fake_dns_supervisor,
                    &intercept_supervisor,
                    app.clone(),
                    state.tls_intercept.clone(),
                    &reloaded_config,
                    state.rules.clone(),
                ).await?;
                active_generation = generation;
                active_config = reloaded_config;
                update_transparent_snapshot(&state.observability, &active_config, &state, active_generation);
                state.observability.record_event(|| {
                    ObservabilityEvent::new(
                        ObservabilityEventLevel::Info,
                        "runtime.transparent_reloaded",
                        format!(
                            "Applied transparent runtime reload generation {} on {}",
                            active_generation,
                            active_config.listen_addr
                        ),
                    )
                });
            }
        }
    }
}

fn build_state(
    config: &AppConfig,
    rules: LiveRuleSet,
    plugins: LivePluginRegistry,
) -> Result<AppState<HyperExecutor>> {
    let executor = HyperExecutor::new()?;
    let tls_intercept = TlsInterceptService::new()?;
    let observability = ObservabilityRuntime::new(&config.observability);

    Ok(AppState {
        executor,
        tls_intercept,
        observability,
        plugins,
        rules,
    })
}

fn maybe_spawn_config_watch(
    watch_config_path: Option<PathBuf>,
    live_rules: LiveRuleSet,
    observability: ObservabilityRuntime,
    config: &AppConfig,
    workers: Workers,
    reload_tx: Option<mpsc::UnboundedSender<ConfigReloadRequest>>,
) -> Option<ShutdownJoinHandle> {
    if let Some(path) = watch_config_path {
        return Some(spawn_config_watch(
            path,
            config,
            live_rules,
            observability,
            workers,
            reload_tx,
        ));
    }

    None
}

fn update_explicit_snapshot(
    observability: &ObservabilityRuntime,
    config: &AppConfig,
    state: &AppState<HyperExecutor>,
    generation: u64,
) {
    let rule_count = state.rules.snapshot().len();
    let plugin_count = state.plugins.len();
    observability.replace_snapshot(|| RuntimeSnapshot {
        listen_addr: Some(config.listen_addr),
        tls_listen_addr: None,
        fake_dns_listen_addr: None,
        active_rule_count: rule_count,
        active_plugin_count: plugin_count,
        reload_generation: generation,
    });
}

fn update_transparent_snapshot(
    observability: &ObservabilityRuntime,
    config: &AppConfig,
    state: &AppState<HyperExecutor>,
    generation: u64,
) {
    let rule_count = state.rules.snapshot().len();
    let plugin_count = state.plugins.len();
    let fake_dns_listen_addr =
        should_start_fake_dns_runtime(&config.backend).then_some(config.backend.dns.listen_addr);
    observability.replace_snapshot(|| RuntimeSnapshot {
        listen_addr: Some(config.listen_addr),
        tls_listen_addr: Some(std::net::SocketAddr::new(
            config.listen_addr.ip(),
            effective_tls_port(config),
        )),
        fake_dns_listen_addr,
        active_rule_count: rule_count,
        active_plugin_count: plugin_count,
        reload_generation: generation,
    });
}

fn take_latest_reload_request(
    initial_request: ConfigReloadRequest,
    reload_rx: &mut mpsc::UnboundedReceiver<ConfigReloadRequest>,
) -> (ConfigReloadRequest, usize) {
    let mut latest_request = initial_request;
    let mut skipped_generations = 0usize;

    while let Ok(next_request) = reload_rx.try_recv() {
        latest_request = next_request;
        skipped_generations += 1;
    }

    (latest_request, skipped_generations)
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
        if let Some(intercept) = self.intercept.take() {
            intercept.shutdown().await;
        }
        if let Some(dns) = self.dns.take() {
            dns.shutdown().await;
        }
        if let Some(http) = self.http.take() {
            http.shutdown().await;
        }
        if let Some(tls) = self.tls.take() {
            tls.shutdown().await;
        }
    }

    async fn reload(
        &mut self,
        listener_supervisor: &ListenerSupervisor,
        fake_dns_supervisor: &FakeDnsSupervisor,
        intercept_supervisor: &InterceptBackendSupervisor,
        app: Router,
        tls_intercept: TlsInterceptService,
        next_config: &AppConfig,
        live_rules: LiveRuleSet,
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
                start_fake_dns_instance(
                    fake_dns_supervisor,
                    &next_config.backend,
                    live_rules.clone(),
                )
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
            self.tls = Some(listener_supervisor.start_tls(
                app.clone(),
                effective_tls_port(next_config),
                tls_intercept,
            )?);
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
    tls_intercept: TlsInterceptService,
    config: &AppConfig,
    live_rules: LiveRuleSet,
) -> Result<TransparentRuntimeHandles> {
    let dns = start_fake_dns_instance(fake_dns_supervisor, &config.backend, live_rules).await?;
    let http = listener_supervisor
        .start_http(app.clone(), config.listen_addr)
        .await?;
    let tls_port = effective_tls_port(config);
    let tls = listener_supervisor.start_tls(app, tls_port, tls_intercept)?;
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
            || current.backend != next.backend
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

async fn start_fake_dns_instance(
    fake_dns_supervisor: &FakeDnsSupervisor,
    backend: &BackendOptions,
    live_rules: LiveRuleSet,
) -> Result<FakeDnsInstance> {
    if should_start_fake_dns_runtime(backend) {
        return fake_dns_supervisor
            .start(backend.dns.clone(), live_rules)
            .await;
    }

    let instance = fake_dns_supervisor.build(backend.dns.clone(), live_rules)?;
    tracing::info!(
        backend_kind = ?backend.kind,
        tun_stack = ?backend.tun.stack,
        "Skipping local fake DNS listener runtime because TUN smoltcp handles DNS in-tunnel"
    );
    Ok(instance)
}

fn should_start_fake_dns_runtime(backend: &BackendOptions) -> bool {
    !(backend.kind == TransparentBackendKind::Tun && backend.tun.stack == TunStack::Smoltcp)
}
