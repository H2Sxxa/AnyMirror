mod fetch;
mod forward;
mod health;
mod proxy_entry;
mod rewrite;
mod shared;
mod state;
mod tls;
mod transparent;

use std::sync::Arc;

use axum::{Router, routing::get};
use reqwest::Client;

use crate::rules::AppConfig;
use state::AppState;

pub async fn serve_explicit(config: AppConfig) -> anyhow::Result<()> {
    let state = build_state(config);
    let listen_addr = state.listen_addr;
    let app = build_common_router()
        .fallback(proxy_entry::proxy_entry)
        .with_state(state);
    serve_app(app, listen_addr).await
}

pub async fn serve_transparent(config: AppConfig) -> anyhow::Result<()> {
    let state = build_state(config.clone());
    let mut listen_addr = state.listen_addr;
    let proxy_redirect_addr = listen_addr;
    listen_addr.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)); // 0.0.0.0
    let app = build_common_router()
        .fallback(transparent::transparent_entry)
        .with_state(state.clone());

    // 解析我们需要拦截的目标域名为 IP，从而让 WinDivert 只拦截这些特定目标的流量
    let mut target_ips = Vec::new();
    for host in config.rules.target_hosts() {
        if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), 0)) {
            for addr in addrs {
                if let std::net::IpAddr::V4(ipv4) = addr.ip() {
                    if !target_ips.contains(&ipv4) {
                        target_ips.push(ipv4);
                    }
                }
            }
        }
    }

    let custom_filter = if target_ips.is_empty() {
        crate::traffic::windivert::default_filter(listen_addr, false)
    } else {
        let ip_conds: Vec<String> = target_ips.iter().map(|ip| format!("ip.DstAddr == {}", ip)).collect();
        format!(
            "outbound and ip and tcp and ( (!loopback and tcp.DstPort != {} and tcp.DstPort != {} and ({})) or tcp.SrcPort == {} or tcp.SrcPort == {} )",
            listen_addr.port(),
            listen_addr.port() + 1,
            ip_conds.join(" or "),
            listen_addr.port(),
            listen_addr.port() + 1
        )
    };

    tracing::info!("WinDivert will filter out these resolved target IPs: {:?}", target_ips);

    // 初始化并启动 WinDivert 流量拦截系统
    let wd_config = crate::traffic::windivert::WinDivertConfig {
        local_proxy_addr: proxy_redirect_addr,
        filter: custom_filter,
        sniff: false,
        ..Default::default()
    };
    let wd_runtime = crate::traffic::windivert::WinDivertRuntime::new(wd_config)?;
    wd_runtime.start()?;
    tracing::info!("WinDivert capturing started: {}", wd_runtime.plan_summary());

    let mut https_listen_addr = listen_addr;
    https_listen_addr.set_port(https_listen_addr.port() + 1);

    let domains: Vec<String> = config.rules.target_hosts().into_iter().collect();

    let app_for_tls = app.clone();
    tokio::spawn(async move {
        let _ = tls::serve_app_tls(app_for_tls, https_listen_addr, domains).await;
    });

    serve_app(app, listen_addr).await
}

fn build_state(config: AppConfig) -> AppState {
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client build should succeed");

    AppState {
        client,
        listen_addr: config.listen_addr,
        rules: Arc::new(config.rules),
    }
}

fn build_common_router() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(health::healthz))
        .route("/rewrite", get(rewrite::rewrite_url))
        .route("/fetch", get(fetch::fetch_url).head(fetch::fetch_url))
}

async fn serve_app(app: Router, listen_addr: std::net::SocketAddr) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shared::shutdown_signal())
        .await?;

    Ok(())
}






