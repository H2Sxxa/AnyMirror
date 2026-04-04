use std::net::SocketAddr;

use anyhow::{Context, Result};
use ipnet::{Ipv4Net, Ipv6Net};
use windivert::{layer::WinDivertLayerTrait, WinDivert};

use crate::config::AppConfig;
use crate::traffic::shared::dns::FakeDnsServer;
use crate::traffic::shared::nat::{
    new_transparent_nat_table, spawn_nat_cleanup_task, TransparentNatTableV4, TransparentNatTableV6,
};
use crate::traffic::windivert::config::{
    RuntimeBackend, TransparentCaptureKind, WinDivertConfig, WinDivertLayer, WinDivertRuntime,
    WindowsBackendPlan,
};
use crate::traffic::windivert::filters;
use crate::workers::Workers;

use super::capture::run_capture_loop;

#[derive(Clone)]
struct TransparentRuntimeContext {
    local_proxy_addr: SocketAddr,
    tls_port: u16,
    local_dns_port: u16,
    fake_ipv4_range: Ipv4Net,
    fake_ipv6_range: Ipv6Net,
    layer: WinDivertLayer,
    fake_dns_server: FakeDnsServer,
    transparent_nat_table_v4: TransparentNatTableV4,
    transparent_nat_table_v6: TransparentNatTableV6,
}

pub fn run_transparent_windivert_runtimes(
    config: &AppConfig,
    fake_dns_server: FakeDnsServer,
    proxy_redirect_addr: SocketAddr,
    workers: Workers,
) -> Result<()> {
    let proxy_port = proxy_redirect_addr.port();
    let tls_port = config.tls_port.unwrap_or(proxy_port + 1);
    let local_dns_port = fake_dns_server.listen_port();
    let fake_ipv4_range = config.backend.dns.fake_ipv4_range;
    let fake_ipv6_range = config.backend.dns.fake_ipv6_range;
    let layer = config.backend.windivert.layer;
    let nat_table_v4: TransparentNatTableV4 = new_transparent_nat_table();
    let nat_table_v6: TransparentNatTableV6 = new_transparent_nat_table();
    let runtime_context = TransparentRuntimeContext {
        local_proxy_addr: proxy_redirect_addr,
        tls_port,
        local_dns_port,
        fake_ipv4_range,
        fake_ipv6_range,
        layer,
        fake_dns_server,
        transparent_nat_table_v4: nat_table_v4.clone(),
        transparent_nat_table_v6: nat_table_v6.clone(),
    };

    spawn_nat_cleanup_task(nat_table_v4.clone(), nat_table_v6.clone(), workers.clone());

    tracing::info!(
        fake_ipv4_range = %fake_ipv4_range,
        fake_ipv6_range = %fake_ipv6_range,
        fake_dns_listen = %runtime_context.fake_dns_server.listen_addr(),
        "WinDivert transparent mode is using fake-ip routing"
    );

    start_transparent_runtime(
        "WinDivert fake-ip DNS responder started",
        runtime_context.build_runtime_config(
            filters::build_transparent_dns_query_filter(),
            TransparentCaptureKind::DnsResponder,
        ),
        None,
        workers.clone(),
    )?;
    start_transparent_runtime(
        "WinDivert DNS-over-TCP redirect started",
        runtime_context.build_runtime_config(
            filters::build_transparent_dns_tcp_request_filter(),
            TransparentCaptureKind::TcpDnsRedirect,
        ),
        Some(local_dns_port),
        workers.clone(),
    )?;
    start_transparent_runtime(
        "WinDivert fake-ip request capture started",
        runtime_context.build_runtime_config(
            filters::build_transparent_fake_ip_tcp_request_filter(
                proxy_port,
                tls_port,
                fake_ipv4_range,
                fake_ipv6_range,
            ),
            TransparentCaptureKind::TcpRequestRedirect,
        ),
        None,
        workers.clone(),
    )?;
    start_transparent_runtime(
        "WinDivert fake-ip QUIC drop strategy started",
        runtime_context.build_runtime_config(
            filters::build_transparent_fake_ip_quic_filter(fake_ipv4_range, fake_ipv6_range),
            TransparentCaptureKind::UdpQuicDrop,
        ),
        None,
        workers.clone(),
    )?;
    start_transparent_runtime(
        "WinDivert fake-ip proxy response capture started",
        runtime_context.build_runtime_config(
            filters::build_transparent_tcp_proxy_response_filter(
                proxy_port,
                tls_port,
                local_dns_port,
            ),
            TransparentCaptureKind::TcpProxyResponse,
        ),
        None,
        workers,
    )?;

    Ok(())
}

impl TransparentRuntimeContext {
    fn build_runtime_config(
        &self,
        filter: String,
        capture_kind: TransparentCaptureKind,
    ) -> WinDivertConfig {
        WinDivertConfig {
            local_proxy_addr: self.local_proxy_addr,
            tls_port: self.tls_port,
            filter,
            layer: self.layer,
            sniff: false,
            fake_ipv4_range: self.fake_ipv4_range,
            fake_ipv6_range: self.fake_ipv6_range,
            local_dns_port: self.local_dns_port,
            capture_kind,
            fake_dns_server: Some(self.fake_dns_server.clone()),
            transparent_nat_table_v4: self.transparent_nat_table_v4.clone(),
            transparent_nat_table_v6: self.transparent_nat_table_v6.clone(),
            ..Default::default()
        }
    }
}

fn start_transparent_runtime(
    message: &'static str,
    config: WinDivertConfig,
    local_dns_port: Option<u16>,
    workers: Workers,
) -> Result<()> {
    let runtime = WinDivertRuntime::new(config)?;
    runtime.start(workers)?;
    match local_dns_port {
        Some(port) => {
            tracing::info!(plan = %runtime.plan_summary(), local_dns_port = port, "{message}");
        }
        None => {
            tracing::info!(plan = %runtime.plan_summary(), "{message}");
        }
    }
    Ok(())
}

impl WinDivertRuntime {
    pub fn start(&self, workers: Workers) -> Result<()> {
        let RuntimeBackend::Windows(plan) = &self.backend;

        let proxy_port = self.config.local_proxy_addr.port();
        let tls_port = self.config.tls_port;
        let local_dns_port = self.config.local_dns_port;
        let fake_ipv4_range = self.config.fake_ipv4_range;
        let fake_ipv6_range = self.config.fake_ipv6_range;
        let capture_kind = self.config.capture_kind.clone();
        let fake_dns_server = self.config.fake_dns_server.clone();
        let nat_table_v4 = self.config.transparent_nat_table_v4.clone();
        let nat_table_v6 = self.config.transparent_nat_table_v6.clone();
        let worker_name = format!("windivert-{:?}", capture_kind);

        match plan.layer {
            WinDivertLayer::Network => {
                let wd = WinDivert::network(&plan.filter, plan.priority, plan.flags)
                    .context("Failed to open WinDivert handle (Network Layer)")?;
                apply_windivert_params(&wd, plan);
                workers.spawn_blocking(worker_name, move || {
                    run_capture_loop(
                        wd,
                        capture_kind,
                        fake_dns_server,
                        fake_ipv4_range,
                        fake_ipv6_range,
                        nat_table_v4,
                        nat_table_v6,
                        proxy_port,
                        tls_port,
                        local_dns_port,
                    );
                });
            }
            WinDivertLayer::NetworkForward => {
                let wd = WinDivert::forward(&plan.filter, plan.priority, plan.flags)
                    .context("Failed to open WinDivert handle (Forward Layer)")?;
                apply_windivert_params(&wd, plan);
                workers.spawn_blocking(worker_name, move || {
                    run_capture_loop(
                        wd,
                        capture_kind,
                        fake_dns_server,
                        fake_ipv4_range,
                        fake_ipv6_range,
                        nat_table_v4,
                        nat_table_v6,
                        proxy_port,
                        tls_port,
                        local_dns_port,
                    );
                });
            }
        }

        Ok(())
    }
}

fn apply_windivert_params<L: WinDivertLayerTrait>(wd: &WinDivert<L>, plan: &WindowsBackendPlan) {
    for (param, value) in plan.param_updates() {
        if let Err(error) = wd.set_param(param, value) {
            tracing::warn!(?param, ?error, "Failed to set WinDivert parameter");
        }
    }
}
