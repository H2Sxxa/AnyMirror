mod config;
mod gateway;
pub mod observability;
mod plugins;
mod rules;
mod socket;
mod supervisors;
mod traffic;
mod watch;
mod workers;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ServerMode {
    Explicit,
    Transparent,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Start proxy in explicit or transparent mode
    #[arg(short, long, value_enum, default_value_t = ServerMode::Explicit)]
    pub mode: ServerMode,

    /// Path to the configuration file
    #[arg(short = 'c', long = "config", default_value = "config.yml")]
    pub config: PathBuf,

    /// Watch the config file and hot reload rules when it changes
    #[arg(long = "watch-config")]
    pub watch_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    let config_path = config::resolve_config_path(&cli.config)?;
    let config = config::load_config(&config_path)?;
    let telemetry_guard = observability::init_tracing(&config.observability)?;
    let workers = workers::Workers::new();

    let banner = cfonts::render(cfonts::Options {
        text: String::from("anymirror"),
        font: cfonts::Fonts::FontBlock,
        colors: vec![cfonts::Colors::Cyan, cfonts::Colors::Blue],
        align: cfonts::Align::Left,
        ..cfonts::Options::default()
    });
    println!("{}", banner.text);

    tracing::info!(
        "anymirror listening on {} with {} include rules in {:?} mode",
        config.listen_addr,
        config.rules.len(),
        cli.mode
    );
    tracing::info!("config loaded from {}", config_path.display());
    if config.observability.enabled {
        tracing::info!(
            service_name = %config.observability.telemetry.service_name,
            otlp_endpoint = %config.observability.telemetry.otlp_endpoint,
            "OpenTelemetry trace export enabled"
        );
    }

    let watch_config_path = cli.watch_config.then_some(config_path.clone());

    let result = match cli.mode {
        ServerMode::Explicit => gateway::serve_explicit(config, watch_config_path, workers).await,
        ServerMode::Transparent => {
            gateway::serve_transparent(config, watch_config_path, workers).await
        }
    };

    result?;
    telemetry_guard.shutdown()?;
    Ok(())
}
