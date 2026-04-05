use std::ffi::CString;
use std::net::SocketAddr;
use std::sync::{Arc, atomic::AtomicBool};

use anyhow::{Context, Result};
use ipnet::{Ipv4Net, Ipv6Net};
use tokio::task::JoinHandle;
use windivert_sys::{WinDivertOpen, WinDivertSetParam};
use windows_legacy::Win32::Foundation::HANDLE;

use crate::config::{WinDivertBackendOptions, WinDivertLayerConfig};
use crate::traffic::TransparentInterceptRuntimeConfig;
use crate::traffic::shared::dns::FakeDnsServer;
use crate::traffic::shared::intercept::TransparentCaptureKind;
use crate::traffic::shared::nat::{
    TransparentNatTableV4, TransparentNatTableV6, new_transparent_nat_table, spawn_nat_cleanup_task,
};
use crate::traffic::windivert::config::{
    RuntimeBackend, WinDivertConfig, WinDivertLayer, WinDivertRuntime, WindowsBackendPlan,
};
use crate::traffic::windivert::filters;
use crate::workers::Workers;

use super::capture::{run_raw_capture_loop, shutdown_raw_handle};

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

pub struct TransparentInterceptHandle {
    nat_cleanup: JoinHandle<()>,
    runtimes: Vec<RunningWinDivertRuntime>,
}

struct RunningWinDivertRuntime {
    handle: HANDLE,
    shutting_down: Arc<AtomicBool>,
    join: JoinHandle<()>,
}

pub fn run_transparent_windivert_runtimes(
    runtime_config: &TransparentInterceptRuntimeConfig,
    backend: &WinDivertBackendOptions,
    fake_dns_server: FakeDnsServer,
    proxy_redirect_addr: SocketAddr,
    workers: Workers,
) -> Result<TransparentInterceptHandle> {
    let proxy_port = proxy_redirect_addr.port();
    let tls_port = runtime_config.tls_port.unwrap_or(proxy_port + 1);
    let local_dns_port = fake_dns_server.listen_port();
    let fake_ipv4_range = runtime_config.fake_ipv4_range;
    let fake_ipv6_range = runtime_config.fake_ipv6_range;
    let layer = map_windivert_layer(backend.layer);
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

    let nat_cleanup =
        spawn_nat_cleanup_task(nat_table_v4.clone(), nat_table_v6.clone(), workers.clone());

    tracing::info!(
        fake_ipv4_range = %fake_ipv4_range,
        fake_ipv6_range = %fake_ipv6_range,
        fake_dns_listen = %runtime_context.fake_dns_server.listen_addr(),
        "WinDivert transparent mode is using fake-ip routing"
    );

    let runtimes = vec![
        start_transparent_runtime(
            "WinDivert fake-ip DNS responder started",
            runtime_context.build_runtime_config(
                filters::build_transparent_dns_query_filter(),
                TransparentCaptureKind::DnsResponder,
            ),
            None,
            workers.clone(),
        )?,
        start_transparent_runtime(
            "WinDivert DNS-over-TCP redirect started",
            runtime_context.build_runtime_config(
                filters::build_transparent_dns_tcp_request_filter(),
                TransparentCaptureKind::TcpDnsRedirect,
            ),
            Some(local_dns_port),
            workers.clone(),
        )?,
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
        )?,
        start_transparent_runtime(
            "WinDivert fake-ip QUIC drop strategy started",
            runtime_context.build_runtime_config(
                filters::build_transparent_fake_ip_quic_filter(fake_ipv4_range, fake_ipv6_range),
                TransparentCaptureKind::UdpQuicDrop,
            ),
            None,
            workers.clone(),
        )?,
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
        )?,
    ];

    Ok(TransparentInterceptHandle {
        nat_cleanup,
        runtimes,
    })
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
) -> Result<RunningWinDivertRuntime> {
    let runtime = WinDivertRuntime::new(config)?;
    let running = runtime.start(workers)?;
    match local_dns_port {
        Some(port) => {
            tracing::info!(plan = %runtime.plan_summary(), local_dns_port = port, "{message}");
        }
        None => {
            tracing::info!(plan = %runtime.plan_summary(), "{message}");
        }
    }
    Ok(running)
}

fn map_windivert_layer(layer: WinDivertLayerConfig) -> WinDivertLayer {
    match layer {
        WinDivertLayerConfig::Network => WinDivertLayer::Network,
        WinDivertLayerConfig::NetworkForward => WinDivertLayer::NetworkForward,
    }
}

impl TransparentInterceptHandle {
    pub async fn shutdown(self) {
        for runtime in &self.runtimes {
            shutdown_raw_handle(runtime.handle, &runtime.shutting_down);
        }
        for runtime in self.runtimes {
            let _ = runtime.join.await;
        }
        self.nat_cleanup.abort();
        let _ = self.nat_cleanup.await;
    }
}

impl WinDivertRuntime {
    fn start(&self, workers: Workers) -> Result<RunningWinDivertRuntime> {
        let RuntimeBackend::Windows(plan) = &self.backend;

        let handle = open_raw_handle(plan).context("Failed to open WinDivert handle")?;
        apply_windivert_params(handle, plan);

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
        let shutting_down = Arc::new(AtomicBool::new(false));
        let loop_shutdown = shutting_down.clone();
        let join = workers.spawn_blocking(worker_name, move || {
            run_raw_capture_loop(
                handle,
                capture_kind,
                fake_dns_server,
                fake_ipv4_range,
                fake_ipv6_range,
                nat_table_v4,
                nat_table_v6,
                proxy_port,
                tls_port,
                local_dns_port,
                loop_shutdown,
            );
        });

        Ok(RunningWinDivertRuntime {
            handle,
            shutting_down,
            join,
        })
    }
}

fn open_raw_handle(plan: &WindowsBackendPlan) -> Result<HANDLE> {
    let filter =
        CString::new(plan.filter.clone()).context("windivert filter contains null byte")?;
    let layer = match plan.layer {
        WinDivertLayer::Network => windivert_sys::WinDivertLayer::Network,
        WinDivertLayer::NetworkForward => windivert_sys::WinDivertLayer::Forward,
    };
    let handle = unsafe { WinDivertOpen(filter.as_ptr(), layer, plan.priority, plan.flags) };
    if handle.is_invalid() {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(handle)
}

fn apply_windivert_params(handle: HANDLE, plan: &WindowsBackendPlan) {
    for (param, value) in plan.param_updates() {
        let result = unsafe { WinDivertSetParam(handle, param, value) };
        if !result.as_bool() {
            let error = std::io::Error::last_os_error();
            tracing::warn!(?param, ?error, "Failed to set WinDivert parameter");
        }
    }
}
