mod config;
mod proxy;
mod rules;
mod socket;
mod traffic;
mod watch;
mod workers;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "anymirror=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    let config_path = config::resolve_config_path(&cli.config)?;
    let config = config::load_config(&config_path)?;
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

    let watch_config_path = cli.watch_config.then_some(config_path.clone());

    match cli.mode {
        ServerMode::Explicit => proxy::serve_explicit(config, watch_config_path, workers).await,
        ServerMode::Transparent => {
            proxy::serve_transparent(config, watch_config_path, workers).await
        }
    }
}
