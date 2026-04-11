use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use tokio::{
    sync::{mpsc, oneshot},
    time,
};

use crate::{
    config::{AppConfig, BackendOptions, PluginRuntimeOptions, load_config},
    observability::{ObservabilityEvent, ObservabilityEventLevel, ObservabilityRuntime},
    rules::pool::LiveRuleSet,
    workers::{ShutdownJoinHandle, Workers},
};

const CONFIG_WATCH_INTERVAL: Duration = Duration::from_secs(1);
const CONFIG_WATCH_STABLE_WINDOW: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
struct StaticConfigSnapshot {
    listen_addr: std::net::SocketAddr,
    tls_port: Option<u16>,
    backend: BackendOptions,
    plugins: PluginRuntimeOptions,
}

#[derive(Debug, Clone)]
pub struct ConfigReloadRequest {
    pub generation: u64,
    pub config: AppConfig,
}

pub fn spawn_config_watch(
    path: PathBuf,
    active_config: &AppConfig,
    live_rules: LiveRuleSet,
    observability: ObservabilityRuntime,
    workers: Workers,
    reload_tx: Option<mpsc::UnboundedSender<ConfigReloadRequest>>,
) -> ShutdownJoinHandle {
    let mut static_config = StaticConfigSnapshot::from_config(active_config);
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let mut next_generation: u64 = 1;

    let join = workers.spawn("config-watch", async move {
        let mut interval = time::interval(CONFIG_WATCH_INTERVAL);
        let mut last_processed_modified = match read_modified_time(&path) {
            Ok(modified_time) => Some(modified_time),
            Err(error) => {
                tracing::warn!(
                    config_path = %path.display(),
                    ?error,
                    "Failed to stat config file before starting hot reload watch"
                );
                None
            }
        };
        let mut pending_modified = None;
        interval.tick().await;

        tracing::info!(
            config_path = %path.display(),
            poll_interval_secs = CONFIG_WATCH_INTERVAL.as_secs(),
            stable_window_secs = CONFIG_WATCH_STABLE_WINDOW.as_secs(),
            "Config watch started"
        );
        observability.record_event(|| {
            ObservabilityEvent::new(
                ObservabilityEventLevel::Info,
                "config_watch.started",
                format!("Started config watch for {}", path.display()),
            )
        });

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    tracing::info!(
                        config_path = %path.display(),
                        "Config watch stopped"
                    );
                    observability.record_event(|| {
                        ObservabilityEvent::new(
                            ObservabilityEventLevel::Info,
                            "config_watch.stopped",
                            format!("Stopped config watch for {}", path.display()),
                        )
                    });
                    return;
                }
                _ = interval.tick() => {}
            }

            let modified_time = match read_modified_time(&path) {
                Ok(modified_time) => modified_time,
                Err(error) => {
                    tracing::warn!(
                        config_path = %path.display(),
                        ?error,
                        "Failed to stat config file during hot reload watch"
                    );
                    continue;
                }
            };

            if last_processed_modified
                .as_ref()
                .is_some_and(|previous| modified_time <= *previous)
            {
                continue;
            }
            if pending_modified != Some(modified_time) {
                pending_modified = Some(modified_time);
                continue;
            }
            if !modified_time_is_stable(modified_time, CONFIG_WATCH_STABLE_WINDOW) {
                continue;
            }

            match load_config(&path) {
                Ok(reloaded_config) => {
                    let runtime_changes =
                        static_config.describe_non_reloadable_changes(&reloaded_config);
                    let rule_count = live_rules.replace(reloaded_config.rules.clone());
                    tracing::info!(
                        config_path = %path.display(),
                        rule_count,
                        "Hot reloaded config rules"
                    );
                    observability.record_event(|| {
                        ObservabilityEvent::new(
                            ObservabilityEventLevel::Info,
                            "config_watch.rules_reloaded",
                            format!(
                                "Reloaded rules from {} with {} active rules",
                                path.display(),
                                rule_count
                            ),
                        )
                    });

                    if let Some(reload_tx) = reload_tx.as_ref() {
                        let next_runtime_snapshot =
                            StaticConfigSnapshot::from_config(&reloaded_config);
                        if runtime_changes.is_empty() {
                            tracing::info!(
                                config_path = %path.display(),
                                generation = next_generation,
                                "Config change only affected live rules or plugins; applying generation without component restarts"
                            );
                        } else {
                            tracing::info!(
                                config_path = %path.display(),
                                generation = next_generation,
                                runtime_changes = %runtime_changes.join("; "),
                                "Config change requires runtime reload"
                            );
                        }

                        let request = ConfigReloadRequest {
                            generation: next_generation,
                            config: reloaded_config,
                        };
                        if let Err(error) = reload_tx.send(request) {
                            tracing::error!(
                                config_path = %path.display(),
                                ?error,
                                "Failed to enqueue runtime reload"
                            );
                            observability.record_event(|| {
                                ObservabilityEvent::new(
                                    ObservabilityEventLevel::Error,
                                    "config_watch.reload_enqueue_failed",
                                    format!(
                                        "Failed to enqueue runtime reload for {}: {}",
                                        path.display(),
                                        error
                                    ),
                                )
                            });
                        } else {
                            static_config = next_runtime_snapshot;
                            next_generation = next_generation.saturating_add(1);
                            observability.record_event(|| {
                                ObservabilityEvent::new(
                                    ObservabilityEventLevel::Info,
                                    "config_watch.reload_enqueued",
                                    format!(
                                        "Enqueued runtime reload generation {} for {}",
                                        next_generation.saturating_sub(1),
                                        path.display()
                                    ),
                                )
                            });
                        }
                    }
                }
                Err(error) => {
                    tracing::error!(
                        config_path = %path.display(),
                        ?error,
                        "Failed to hot reload config file"
                    );
                    observability.record_event(|| {
                        ObservabilityEvent::new(
                            ObservabilityEventLevel::Error,
                            "config_watch.reload_failed",
                            format!("Failed to reload config {}: {}", path.display(), error),
                        )
                    });
                }
            }

            last_processed_modified = Some(modified_time);
            pending_modified = None;
        }
    });

    ShutdownJoinHandle::new(shutdown_tx, join)
}

impl StaticConfigSnapshot {
    fn from_config(config: &AppConfig) -> Self {
        Self {
            listen_addr: config.listen_addr,
            tls_port: config.tls_port,
            backend: config.backend.clone(),
            plugins: config.plugins.clone(),
        }
    }

    fn describe_non_reloadable_changes(&self, config: &AppConfig) -> Vec<String> {
        let mut changes = Vec::new();

        if config.listen_addr != self.listen_addr {
            changes.push(format!(
                "listen changed from {} to {}",
                self.listen_addr, config.listen_addr
            ));
        }

        if config.tls_port != self.tls_port {
            changes.push(format!(
                "tls_port changed from {:?} to {:?}",
                self.tls_port, config.tls_port
            ));
        }

        if config.backend != self.backend {
            changes.push("backend settings changed".to_string());
        }

        if config.plugins != self.plugins {
            changes.push("plugin settings changed".to_string());
        }

        changes
    }
}

fn read_modified_time(path: &Path) -> std::io::Result<SystemTime> {
    fs::metadata(path)?.modified()
}

fn modified_time_is_stable(modified_time: SystemTime, stable_window: Duration) -> bool {
    SystemTime::now()
        .duration_since(modified_time)
        .map(|age| age >= stable_window)
        .unwrap_or(false)
}
