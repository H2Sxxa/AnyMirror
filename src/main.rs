mod config;
mod proxy;
mod rules;
mod traffic;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ServerMode {
    Explicit,
    Transparent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CaptureLayer {
    /// Intercept local network traffic (default)
    Network,
    /// Intercept forwarded network traffic (e.g. from WSL, virtual machines or LAN)
    NetworkForward,
}

impl From<CaptureLayer> for traffic::windivert::WinDivertLayer {
    fn from(layer: CaptureLayer) -> Self {
        match layer {
            CaptureLayer::Network => traffic::windivert::WinDivertLayer::Network,
            CaptureLayer::NetworkForward => traffic::windivert::WinDivertLayer::NetworkForward,
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Start proxy in explicit or transparent mode
    #[arg(short, long, value_enum, default_value_t = ServerMode::Explicit)]
    pub mode: ServerMode,

    /// Specifies the WinDivert capture layer to use when using transparent mode
    #[arg(short, long, value_enum, default_value_t = CaptureLayer::Network)]
    pub layer: CaptureLayer,

    /// Path to the configuration file
    #[arg(short = 'c', long = "config", default_value = "config.yml")]
    pub config: PathBuf,
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
    let config = config::load_config(&cli.config)?;

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
    tracing::info!("config loaded from {}", cli.config.display());

    match cli.mode {
        ServerMode::Explicit => proxy::serve_explicit(config).await,
        ServerMode::Transparent => proxy::serve_transparent(config, cli.layer.into()).await,
    }
}
