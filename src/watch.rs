use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use tokio::time;

use crate::{
    config::{load_config, AppConfig, BackendOptions},
    rules::pool::LiveRules,
    workers::Workers,
};

const CONFIG_WATCH_INTERVAL: Duration = Duration::from_secs(1);
const CONFIG_WATCH_STABLE_WINDOW: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
struct StaticConfigSnapshot {
    listen_addr: std::net::SocketAddr,
    tls_port: Option<u16>,
    backend: BackendOptions,
}

pub fn spawn_config_watch(
    path: PathBuf,
    active_config: &AppConfig,
    live_rules: LiveRules,
    workers: Workers,
) {
    let static_config = StaticConfigSnapshot::from_config(active_config);

    workers.spawn("config-watch", async move {
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

        loop {
            interval.tick().await;

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
                    let immutable_changes =
                        static_config.describe_non_reloadable_changes(&reloaded_config);
                    let rule_count = live_rules.replace(reloaded_config.rules);
                    tracing::info!(
                        config_path = %path.display(),
                        rule_count,
                        "Hot reloaded config rules"
                    );

                    if !immutable_changes.is_empty() {
                        tracing::warn!(
                            config_path = %path.display(),
                            non_reloadable_changes = %immutable_changes.join("; "),
                            "Config contains changes that still require restart"
                        );
                    }
                }
                Err(error) => {
                    tracing::error!(
                        config_path = %path.display(),
                        ?error,
                        "Failed to hot reload config file"
                    );
                }
            }

            last_processed_modified = Some(modified_time);
            pending_modified = None;
        }
    });
}

impl StaticConfigSnapshot {
    fn from_config(config: &AppConfig) -> Self {
        Self {
            listen_addr: config.listen_addr,
            tls_port: config.tls_port,
            backend: config.backend.clone(),
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
