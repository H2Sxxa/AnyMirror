mod proxy;
mod rules;
mod traffic;

use std::{env, path::PathBuf};

use anyhow::{Result, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerMode {
    Explicit,
    Transparent,
}
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "anymirror=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let banner = cfonts::render(cfonts::Options {
        text: String::from("anymirror"),
        font: cfonts::Fonts::FontBlock,
        colors: vec![cfonts::Colors::Cyan, cfonts::Colors::Blue],
        align: cfonts::Align::Left,
        ..cfonts::Options::default()
    });
    println!("{}", banner.text);

    let _ = rustls::crypto::ring::default_provider().install_default();

    let (mode, config_path) = resolve_cli_args()?;
    let config = rules::load_config(&config_path)?;

    tracing::info!(
        "anymirror listening on {} with {} include rules in {:?} mode",
        config.listen_addr,
        config.rules.len(),
        mode
    );
    tracing::info!("config loaded from {}", config_path.display());

    match mode {
        ServerMode::Explicit => proxy::serve_explicit(config).await,
        ServerMode::Transparent => proxy::serve_transparent(config).await,
    }
}

fn resolve_cli_args() -> Result<(ServerMode, PathBuf)> {
    let mut mode = ServerMode::Explicit;
    let mut config_path = None;

    for arg in env::args_os().skip(1) {
        match arg.to_str() {
            Some("--transparent") => mode = ServerMode::Transparent,
            Some("--explicit") => mode = ServerMode::Explicit,
            Some(flag) if flag.starts_with("--") => {
                bail!("unsupported flag `{flag}`; expected --explicit or --transparent")
            }
            _ => {
                if config_path.is_some() {
                    bail!("only a single config path argument is supported");
                }
                config_path = Some(PathBuf::from(arg));
            }
        }
    }

    Ok((
        mode,
        config_path.unwrap_or_else(|| PathBuf::from("config.yml")),
    ))
}
