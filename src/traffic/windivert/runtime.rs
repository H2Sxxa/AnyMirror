use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};

use anyhow::{bail, Context, Result};
use tokio::{
    sync::mpsc::{unbounded_channel, UnboundedReceiver},
    task::JoinHandle,
};

use crate::config::AppConfig;
use crate::rules::Rules;

use super::{
    config::{
        RuntimeBackend, TransparentCaptureKind, WinDivertConfig, WinDivertLayer, WinDivertRuntime,
    },
    dns::parse_dns_response,
    filters,
    payload::extract_host,
    state::{
        new_transparent_nat_table_v4, new_transparent_nat_table_v6, spawn_nat_cleanup_task,
        spawn_target_store_cleanup_task, touch_nat_mapping_v4, touch_nat_mapping_v6,
        upsert_nat_mapping_v4, upsert_nat_mapping_v6, TransparentNatTableV4, TransparentNatTableV6,
        TransparentTargetChangeTx, TransparentTargetStore, NAT_ENTRY_CLOSING_TTL,
        NAT_ENTRY_ESTABLISHED_TTL, REQUEST_GENERATION_DEBOUNCE, REQUEST_GENERATION_GRACE_PERIOD,
        REQUEST_PRIORITY_BASE,
    },
};

#[cfg(target_os = "windows")]
use windivert::{CloseAction, WinDivert};
#[cfg(target_os = "windows")]
use windivert_sys::WinDivertShutdownMode;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::HANDLE;

#[derive(Debug)]
struct RunningWinDivert {
    #[cfg(target_os = "windows")]
    handle: HANDLE,
    join_handle: JoinHandle<()>,
    stop_requested: Arc<AtomicBool>,
}

#[derive(Debug)]
struct RequestGeneration {
    runtime: RunningWinDivert,
    target_ips: Vec<IpAddr>,
}

pub fn resolve_origin_target_ips(rules: &Rules) -> HashSet<IpAddr> {
    let mut target_ips = HashSet::new();
    for host in rules.origin_hosts() {
        if let Ok(addrs) = ToSocketAddrs::to_socket_addrs(&(host.as_str(), 0)) {
            for addr in addrs {
                target_ips.insert(addr.ip());
            }
        }
    }
    target_ips
}

pub fn run_transparent_windivert_runtimes(
    config: &AppConfig,
    proxy_redirect_addr: SocketAddr,
    layer: WinDivertLayer,
) -> Result<()> {
    let now = Instant::now();
    let proxy_port = proxy_redirect_addr.port();
    let tls_port = config.tls_port.unwrap_or(proxy_port + 1);
    let origin_hosts = config.rules.origin_hosts();
    let target_store =
        TransparentTargetStore::from_bootstrap(resolve_origin_target_ips(&config.rules), now);
    let nat_table_v4 = new_transparent_nat_table_v4();
    let nat_table_v6 = new_transparent_nat_table_v6();

    tracing::info!(
        target_ips = ?target_store.snapshot_active_ips(now),
        hot_reload = config.windivert.hot_reload,
        "WinDivert bootstrap target IPs resolved"
    );

    spawn_nat_cleanup_task(nat_table_v4.clone(), nat_table_v6.clone());

    let target_change_tx = if config.windivert.hot_reload {
        let (target_change_tx, target_change_rx) = unbounded_channel();
        spawn_target_store_cleanup_task(target_store.clone(), Some(target_change_tx.clone()));
        spawn_request_generation_manager(
            target_change_rx,
            proxy_redirect_addr,
            tls_port,
            layer,
            origin_hosts.clone(),
            target_store.clone(),
            nat_table_v4.clone(),
            nat_table_v6.clone(),
        );
        Some(target_change_tx)
    } else {
        spawn_target_store_cleanup_task(target_store.clone(), None);

        let request_runtime = WinDivertRuntime::new(WinDivertConfig {
            local_proxy_addr: proxy_redirect_addr,
            tls_port,
            filter: filters::build_transparent_tcp_request_filter(proxy_port, tls_port),
            sniff: false,
            layer,
            capture_kind: TransparentCaptureKind::TcpRequestRedirect,
            transparent_hosts: origin_hosts.clone(),
            transparent_target_store: target_store.clone(),
            transparent_nat_table_v4: nat_table_v4.clone(),
            transparent_nat_table_v6: nat_table_v6.clone(),
            target_change_tx: None,
            ..Default::default()
        })?;
        let _request_runtime = request_runtime.start()?;
        tracing::info!(
            plan = %request_runtime.plan_summary(),
            "WinDivert broad request capture started"
        );

        None
    };

    let response_runtime = WinDivertRuntime::new(WinDivertConfig {
        local_proxy_addr: proxy_redirect_addr,
        tls_port,
        filter: filters::build_transparent_tcp_proxy_response_filter(proxy_port, tls_port),
        sniff: false,
        layer,
        capture_kind: TransparentCaptureKind::TcpProxyResponse,
        transparent_hosts: origin_hosts.clone(),
        transparent_target_store: target_store.clone(),
        transparent_nat_table_v4: nat_table_v4.clone(),
        transparent_nat_table_v6: nat_table_v6.clone(),
        target_change_tx: None,
        ..Default::default()
    })?;
    let _response_runtime = response_runtime.start()?;
    tracing::info!(
        plan = %response_runtime.plan_summary(),
        "WinDivert proxy response capture started"
    );

    let dns_runtime = WinDivertRuntime::new(WinDivertConfig {
        local_proxy_addr: proxy_redirect_addr,
        tls_port,
        filter: filters::build_transparent_dns_filter(),
        sniff: true,
        layer,
        capture_kind: TransparentCaptureKind::DnsSniffer,
        transparent_hosts: origin_hosts,
        transparent_target_store: target_store,
        transparent_nat_table_v4: nat_table_v4,
        transparent_nat_table_v6: nat_table_v6,
        target_change_tx,
        ..Default::default()
    })?;
    let _dns_runtime = dns_runtime.start()?;
    tracing::info!(
        plan = %dns_runtime.plan_summary(),
        "WinDivert DNS sniffing started"
    );

    Ok(())
}

fn spawn_request_generation_manager(
    mut target_change_rx: UnboundedReceiver<()>,
    proxy_redirect_addr: SocketAddr,
    tls_port: u16,
    layer: WinDivertLayer,
    origin_hosts: HashSet<String>,
    target_store: TransparentTargetStore,
    nat_table_v4: TransparentNatTableV4,
    nat_table_v6: TransparentNatTableV6,
) {
    tokio::spawn(async move {
        let mut generation_index = 0u64;
        let mut active_generation: Option<RequestGeneration> = None;

        let initial_snapshot = target_store.snapshot_active_ips(Instant::now());
        if let Some(generation) = start_request_generation(
            generation_index,
            initial_snapshot,
            proxy_redirect_addr,
            tls_port,
            layer,
            origin_hosts.clone(),
            target_store.clone(),
            nat_table_v4.clone(),
            nat_table_v6.clone(),
        ) {
            active_generation = Some(generation);
            generation_index += 1;
        }

        while target_change_rx.recv().await.is_some() {
            tokio::time::sleep(REQUEST_GENERATION_DEBOUNCE).await;
            while target_change_rx.try_recv().is_ok() {}

            let next_snapshot = target_store.snapshot_active_ips(Instant::now());
            if active_generation
                .as_ref()
                .is_some_and(|generation| generation.target_ips == next_snapshot)
            {
                continue;
            }

            if next_snapshot.is_empty() {
                let previous_generation = active_generation.take();
                if let Some(previous_generation) = previous_generation {
                    tokio::spawn(async move {
                        tokio::time::sleep(REQUEST_GENERATION_GRACE_PERIOD).await;
                        previous_generation.runtime.stop().await;
                    });
                }
                continue;
            }

            let Some(next_generation) = start_request_generation(
                generation_index,
                next_snapshot,
                proxy_redirect_addr,
                tls_port,
                layer,
                origin_hosts.clone(),
                target_store.clone(),
                nat_table_v4.clone(),
                nat_table_v6.clone(),
            ) else {
                continue;
            };

            let previous_generation = active_generation.replace(next_generation);
            generation_index += 1;

            if let Some(previous_generation) = previous_generation {
                tokio::spawn(async move {
                    tokio::time::sleep(REQUEST_GENERATION_GRACE_PERIOD).await;
                    previous_generation.runtime.stop().await;
                });
            }
        }
    });
}

fn start_request_generation(
    generation_index: u64,
    target_ips: Vec<IpAddr>,
    proxy_redirect_addr: SocketAddr,
    tls_port: u16,
    layer: WinDivertLayer,
    origin_hosts: HashSet<String>,
    target_store: TransparentTargetStore,
    nat_table_v4: TransparentNatTableV4,
    nat_table_v6: TransparentNatTableV6,
) -> Option<RequestGeneration> {
    let filter = filters::build_transparent_targeted_tcp_request_filter(
        proxy_redirect_addr.port(),
        tls_port,
        &target_ips,
    )?;

    let priority = REQUEST_PRIORITY_BASE.saturating_add(generation_index as i16);
    let request_runtime = match WinDivertRuntime::new(WinDivertConfig {
        local_proxy_addr: proxy_redirect_addr,
        tls_port,
        filter,
        layer,
        priority,
        sniff: false,
        capture_kind: TransparentCaptureKind::TcpRequestRedirect,
        transparent_hosts: origin_hosts,
        transparent_target_store: target_store,
        transparent_nat_table_v4: nat_table_v4,
        transparent_nat_table_v6: nat_table_v6,
        target_change_tx: None,
        ..Default::default()
    }) {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(?error, "Failed to prepare WinDivert request generation");
            return None;
        }
    };

    let running_runtime = match request_runtime.start() {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(?error, "Failed to start WinDivert request generation");
            return None;
        }
    };

    tracing::info!(
        generation = generation_index,
        target_count = target_ips.len(),
        plan = %request_runtime.plan_summary(),
        "WinDivert targeted request generation started"
    );

    Some(RequestGeneration {
        runtime: running_runtime,
        target_ips,
    })
}

impl RunningWinDivert {
    #[cfg(target_os = "windows")]
    async fn stop(self) {
        self.stop_requested.store(true, Ordering::Relaxed);
        let shutdown_res =
            unsafe { windivert_sys::WinDivertShutdown(self.handle, WinDivertShutdownMode::Both) };
        if !shutdown_res.as_bool() {
            tracing::warn!(
                last_os_error = ?std::io::Error::last_os_error(),
                "Failed to shutdown WinDivert handle"
            );
        }

        let _ = self.join_handle.await;
    }

    #[cfg(not(target_os = "windows"))]
    async fn stop(self) {
        let _ = self.join_handle.await;
    }
}

// Extension for WinDivertRuntime - start() implementation
impl WinDivertRuntime {
    #[cfg(target_os = "windows")]
    fn start(&self) -> Result<RunningWinDivert> {
        let RuntimeBackend::Windows(plan) = &self.backend else {
            bail!("WinDivert backend plan is missing on Windows");
        };

        let proxy_port = self.config.local_proxy_addr.port();
        let tls_port = self.config.tls_port;
        let capture_kind = self.config.capture_kind.clone();
        let origin_hosts = self.config.transparent_hosts.clone();
        let target_store = self.config.transparent_target_store.clone();
        let nat_table_v4 = self.config.transparent_nat_table_v4.clone();
        let nat_table_v6 = self.config.transparent_nat_table_v6.clone();
        let target_change_tx = self.config.target_change_tx.clone();
        let stop_requested = Arc::new(AtomicBool::new(false));
        let plan_summary = self.plan_summary();

        match plan.layer {
            WinDivertLayer::Network => {
                let mut wd = WinDivert::network(&plan.filter, plan.priority, plan.flags)
                    .context("Failed to open WinDivert handle (Network Layer)")?;
                let raw_handle = unsafe { extract_raw_handle(&wd) };
                apply_windivert_params(&wd, plan);
                let stop_requested_for_worker = stop_requested.clone();
                let join_handle = tokio::task::spawn_blocking(move || {
                    let _ = run_network_capture_loop(
                        &mut wd,
                        capture_kind,
                        origin_hosts,
                        target_store,
                        nat_table_v4,
                        nat_table_v6,
                        target_change_tx,
                        proxy_port,
                        tls_port,
                        stop_requested_for_worker,
                    );
                });

                tracing::debug!(plan = %plan_summary, "WinDivert runtime worker spawned");
                Ok(RunningWinDivert {
                    handle: raw_handle,
                    join_handle,
                    stop_requested,
                })
            }
            WinDivertLayer::NetworkForward => {
                let mut wd = WinDivert::forward(&plan.filter, plan.priority, plan.flags)
                    .context("Failed to open WinDivert handle (Forward Layer)")?;
                let raw_handle = unsafe { extract_raw_handle(&wd) };
                apply_windivert_params(&wd, plan);
                let stop_requested_for_worker = stop_requested.clone();
                let join_handle = tokio::task::spawn_blocking(move || {
                    let _ = run_forward_capture_loop(
                        &mut wd,
                        capture_kind,
                        origin_hosts,
                        target_store,
                        nat_table_v4,
                        nat_table_v6,
                        target_change_tx,
                        proxy_port,
                        tls_port,
                        stop_requested_for_worker,
                    );
                });

                tracing::debug!(plan = %plan_summary, "WinDivert runtime worker spawned");
                Ok(RunningWinDivert {
                    handle: raw_handle,
                    join_handle,
                    stop_requested,
                })
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn start(&self) -> Result<RunningWinDivert> {
        bail!("WinDivert backend is not supported on this platform.");
    }
}

#[cfg(target_os = "windows")]
fn apply_windivert_params<L: windivert::layer::WinDivertLayerTrait>(
    wd: &WinDivert<L>,
    plan: &super::config::WindowsBackendPlan,
) {
    for (param, value) in plan.param_updates() {
        if let Err(error) = wd.set_param(param, value) {
            tracing::warn!(?param, ?error, "Failed to set WinDivert parameter");
        }
    }
}

#[cfg(target_os = "windows")]
fn run_network_capture_loop(
    wd: &mut WinDivert<windivert::layer::NetworkLayer>,
    capture_kind: TransparentCaptureKind,
    origin_hosts: HashSet<String>,
    target_store: TransparentTargetStore,
    nat_table_v4: TransparentNatTableV4,
    nat_table_v6: TransparentNatTableV6,
    target_change_tx: Option<TransparentTargetChangeTx>,
    proxy_port: u16,
    tls_port: u16,
    stop_requested: Arc<AtomicBool>,
) -> Result<()> {
    let mut rx_buf = vec![0u8; 65535];
    loop {
        match wd.recv(Some(&mut rx_buf)) {
            Ok(mut packet) => {
                let modified = process_packet(
                    packet.data.to_mut(),
                    &mut packet.address,
                    &capture_kind,
                    &origin_hosts,
                    &target_store,
                    &nat_table_v4,
                    &nat_table_v6,
                    target_change_tx.as_ref(),
                    proxy_port,
                    tls_port,
                );
                if modified {
                    let _ = packet.recalculate_checksums(windivert_sys::ChecksumFlags::new());
                }
                if let Err(error) = wd.send(&packet) {
                    tracing::error!(?error, "WinDivert send failed");
                }
            }
            Err(error) => {
                if stop_requested.load(Ordering::Relaxed) {
                    tracing::debug!(?error, "WinDivert recv loop stopped");
                } else {
                    tracing::error!(?error, "WinDivert recv failed");
                }
                break;
            }
        }
    }

    let _ = wd.close(CloseAction::Nothing);
    Ok(())
}

#[cfg(target_os = "windows")]
fn run_forward_capture_loop(
    wd: &mut WinDivert<windivert::layer::ForwardLayer>,
    capture_kind: TransparentCaptureKind,
    origin_hosts: HashSet<String>,
    target_store: TransparentTargetStore,
    nat_table_v4: TransparentNatTableV4,
    nat_table_v6: TransparentNatTableV6,
    target_change_tx: Option<TransparentTargetChangeTx>,
    proxy_port: u16,
    tls_port: u16,
    stop_requested: Arc<AtomicBool>,
) -> Result<()> {
    let mut rx_buf = vec![0u8; 65535];
    loop {
        match wd.recv(Some(&mut rx_buf)) {
            Ok(mut packet) => {
                let modified = process_packet(
                    packet.data.to_mut(),
                    &mut packet.address,
                    &capture_kind,
                    &origin_hosts,
                    &target_store,
                    &nat_table_v4,
                    &nat_table_v6,
                    target_change_tx.as_ref(),
                    proxy_port,
                    tls_port,
                );
                if modified {
                    let _ = packet.recalculate_checksums(windivert_sys::ChecksumFlags::new());
                }
                if let Err(error) = wd.send(&packet) {
                    tracing::error!(?error, "WinDivert send failed");
                }
            }
            Err(error) => {
                if stop_requested.load(Ordering::Relaxed) {
                    tracing::debug!(?error, "WinDivert recv loop stopped");
                } else {
                    tracing::error!(?error, "WinDivert recv failed");
                }
                break;
            }
        }
    }

    let _ = wd.close(CloseAction::Nothing);
    Ok(())
}

#[cfg(target_os = "windows")]
fn process_packet<A>(
    data: &mut [u8],
    address: &mut A,
    capture_kind: &TransparentCaptureKind,
    origin_hosts: &HashSet<String>,
    target_store: &TransparentTargetStore,
    nat_table_v4: &TransparentNatTableV4,
    nat_table_v6: &TransparentNatTableV6,
    target_change_tx: Option<&TransparentTargetChangeTx>,
    proxy_port: u16,
    tls_port: u16,
) -> bool
where
    A: SetOutboundFlag,
{
    match capture_kind {
        TransparentCaptureKind::DnsSniffer => {
            handle_dns_packet(data, origin_hosts, target_store, target_change_tx);
            false
        }
        TransparentCaptureKind::TcpRequestRedirect => handle_request_packet(
            data,
            address,
            target_store,
            nat_table_v4,
            nat_table_v6,
            proxy_port,
            tls_port,
        ),
        TransparentCaptureKind::TcpProxyResponse => handle_proxy_response_packet(
            data,
            address,
            nat_table_v4,
            nat_table_v6,
            proxy_port,
            tls_port,
        ),
        TransparentCaptureKind::Generic => false,
    }
}

#[cfg(target_os = "windows")]
fn handle_dns_packet(
    data: &[u8],
    origin_hosts: &HashSet<String>,
    target_store: &TransparentTargetStore,
    target_change_tx: Option<&TransparentTargetChangeTx>,
) {
    let now = Instant::now();
    let resolved_targets = extract_dns_targets(data, origin_hosts);
    if resolved_targets.is_empty() {
        return;
    }

    let inserted_targets = target_store.insert_dns_targets(&resolved_targets, now);
    for target in &resolved_targets {
        tracing::info!(
            target_ip = %target.ip,
            ttl_secs = target.ttl.as_secs(),
            "WinDivert sniffed DNS target"
        );
    }

    if !inserted_targets.is_empty() {
        tracing::info!(inserted_targets = ?inserted_targets, "WinDivert activated new DNS target IPs");
        if let Some(target_change_tx) = target_change_tx {
            let _ = target_change_tx.send(());
        }
    }
}

#[cfg(target_os = "windows")]
fn extract_dns_targets(
    data: &[u8],
    origin_hosts: &HashSet<String>,
) -> Vec<super::dns::DnsResolvedTarget> {
    if let Ok(ipv4_slice) = etherparse::Ipv4HeaderSlice::from_slice(data) {
        let ip_header_len = ipv4_slice.slice().len();
        if ipv4_slice.protocol() == etherparse::IpNumber::UDP && data.len() >= ip_header_len + 8 {
            let src_port = u16::from_be_bytes([data[ip_header_len], data[ip_header_len + 1]]);
            if src_port == 53 {
                let dns_payload = &data[ip_header_len + 8..];
                return parse_dns_response(dns_payload, origin_hosts).unwrap_or_default();
            }
        }
    } else if let Ok(ipv6_slice) = etherparse::Ipv6HeaderSlice::from_slice(data) {
        let ip_header_len = ipv6_slice.slice().len();
        if ipv6_slice.next_header() == etherparse::IpNumber::UDP && data.len() >= ip_header_len + 8
        {
            let src_port = u16::from_be_bytes([data[ip_header_len], data[ip_header_len + 1]]);
            if src_port == 53 {
                let dns_payload = &data[ip_header_len + 8..];
                return parse_dns_response(dns_payload, origin_hosts).unwrap_or_default();
            }
        }
    }

    Vec::new()
}

#[cfg(target_os = "windows")]
fn handle_request_packet<A>(
    data: &mut [u8],
    address: &mut A,
    target_store: &TransparentTargetStore,
    nat_table_v4: &TransparentNatTableV4,
    nat_table_v6: &TransparentNatTableV6,
    proxy_port: u16,
    tls_port: u16,
) -> bool
where
    A: SetOutboundFlag,
{
    if let Some(ip_header_len) = match etherparse::Ipv4HeaderSlice::from_slice(data) {
        Ok(ipv4_slice) if ipv4_slice.protocol() == etherparse::IpNumber::TCP => {
            Some(ipv4_slice.slice().len())
        }
        _ => None,
    } {
        return handle_request_packet_v4(
            data,
            address,
            ip_header_len,
            target_store,
            nat_table_v4,
            proxy_port,
            tls_port,
        );
    }

    if let Some(ip_header_len) = match etherparse::Ipv6HeaderSlice::from_slice(data) {
        Ok(ipv6_slice) if ipv6_slice.next_header() == etherparse::IpNumber::TCP => {
            Some(ipv6_slice.slice().len())
        }
        _ => None,
    } {
        return handle_request_packet_v6(
            data,
            address,
            ip_header_len,
            target_store,
            nat_table_v6,
            proxy_port,
            tls_port,
        );
    }

    false
}

#[cfg(target_os = "windows")]
fn handle_proxy_response_packet<A>(
    data: &mut [u8],
    address: &mut A,
    nat_table_v4: &TransparentNatTableV4,
    nat_table_v6: &TransparentNatTableV6,
    proxy_port: u16,
    tls_port: u16,
) -> bool
where
    A: SetOutboundFlag,
{
    if let Some(ip_header_len) = match etherparse::Ipv4HeaderSlice::from_slice(data) {
        Ok(ipv4_slice) if ipv4_slice.protocol() == etherparse::IpNumber::TCP => {
            Some(ipv4_slice.slice().len())
        }
        _ => None,
    } {
        return handle_proxy_response_packet_v4(
            data,
            address,
            ip_header_len,
            nat_table_v4,
            proxy_port,
            tls_port,
        );
    }

    if let Some(ip_header_len) = match etherparse::Ipv6HeaderSlice::from_slice(data) {
        Ok(ipv6_slice) if ipv6_slice.next_header() == etherparse::IpNumber::TCP => {
            Some(ipv6_slice.slice().len())
        }
        _ => None,
    } {
        return handle_proxy_response_packet_v6(
            data,
            address,
            ip_header_len,
            nat_table_v6,
            proxy_port,
            tls_port,
        );
    }

    false
}

#[cfg(target_os = "windows")]
fn handle_request_packet_v4<A>(
    data: &mut [u8],
    address: &mut A,
    ip_header_len: usize,
    target_store: &TransparentTargetStore,
    nat_table_v4: &TransparentNatTableV4,
    proxy_port: u16,
    tls_port: u16,
) -> bool
where
    A: SetOutboundFlag,
{
    if data.len() < ip_header_len + 20 {
        return false;
    }

    let src_ip = std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let src_port = u16::from_be_bytes([data[ip_header_len], data[ip_header_len + 1]]);
    let dst_port = u16::from_be_bytes([data[ip_header_len + 2], data[ip_header_len + 3]]);
    if dst_port == proxy_port || dst_port == tls_port {
        return false;
    }

    if !target_store.contains(&IpAddr::V4(dst_ip), Instant::now()) {
        return false;
    }

    let (tcp_header_len, syn, is_closing) =
        match etherparse::TcpHeaderSlice::from_slice(&data[ip_header_len..]) {
            Ok(tcp_slice) => (
                tcp_slice.slice().len(),
                tcp_slice.syn(),
                tcp_slice.fin() || tcp_slice.rst(),
            ),
            Err(_) => return false,
        };
    let expires_at = nat_expiration(Instant::now(), is_closing);
    if !upsert_nat_mapping_v4(nat_table_v4, src_ip, src_port, dst_ip, dst_port, expires_at) {
        tracing::error!("WinDivert IPv4 NAT table lock poisoned");
        return false;
    }

    let target_proxy_port = if dst_port == 443 {
        tls_port
    } else {
        proxy_port
    };
    data[16..20].copy_from_slice(&src_ip.octets());
    data[ip_header_len + 2..ip_header_len + 4].copy_from_slice(&target_proxy_port.to_be_bytes());

    let mut host_info = String::new();
    if ip_header_len + tcp_header_len < data.len() {
        let payload = &data[ip_header_len + tcp_header_len..];
        if let Some(host) = extract_host(payload) {
            host_info = host;
        }
    }

    address.set_outbound_flag(false);
    if syn || !host_info.is_empty() {
        tracing::info!(
            client_port = src_port,
            destination_ip = %dst_ip,
            destination_port = dst_port,
            target_proxy_port,
            host = host_info,
            "Intercepted IPv4 request and redirected it to the local proxy"
        );
    }

    true
}

#[cfg(target_os = "windows")]
fn handle_request_packet_v6<A>(
    data: &mut [u8],
    address: &mut A,
    ip_header_len: usize,
    target_store: &TransparentTargetStore,
    nat_table_v6: &TransparentNatTableV6,
    proxy_port: u16,
    tls_port: u16,
) -> bool
where
    A: SetOutboundFlag,
{
    if data.len() < ip_header_len + 20 {
        return false;
    }

    let src_ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).unwrap_or_default());
    let dst_ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap_or_default());
    let src_port = u16::from_be_bytes([data[ip_header_len], data[ip_header_len + 1]]);
    let dst_port = u16::from_be_bytes([data[ip_header_len + 2], data[ip_header_len + 3]]);
    if dst_port == proxy_port || dst_port == tls_port {
        return false;
    }

    if !target_store.contains(&IpAddr::V6(dst_ip), Instant::now()) {
        return false;
    }

    let (tcp_header_len, syn, is_closing) =
        match etherparse::TcpHeaderSlice::from_slice(&data[ip_header_len..]) {
            Ok(tcp_slice) => (
                tcp_slice.slice().len(),
                tcp_slice.syn(),
                tcp_slice.fin() || tcp_slice.rst(),
            ),
            Err(_) => return false,
        };
    let expires_at = nat_expiration(Instant::now(), is_closing);
    if !upsert_nat_mapping_v6(nat_table_v6, src_ip, src_port, dst_ip, dst_port, expires_at) {
        tracing::error!("WinDivert IPv6 NAT table lock poisoned");
        return false;
    }

    let target_proxy_port = if dst_port == 443 {
        tls_port
    } else {
        proxy_port
    };
    data[24..40].copy_from_slice(&src_ip.octets());
    data[ip_header_len + 2..ip_header_len + 4].copy_from_slice(&target_proxy_port.to_be_bytes());

    let mut host_info = String::new();
    if ip_header_len + tcp_header_len < data.len() {
        let payload = &data[ip_header_len + tcp_header_len..];
        if let Some(host) = extract_host(payload) {
            host_info = host;
        }
    }

    address.set_outbound_flag(false);
    if syn || !host_info.is_empty() {
        tracing::info!(
            client_port = src_port,
            destination_ip = %dst_ip,
            destination_port = dst_port,
            target_proxy_port,
            host = host_info,
            "Intercepted IPv6 request and redirected it to the local proxy"
        );
    }

    true
}

#[cfg(target_os = "windows")]
fn handle_proxy_response_packet_v4<A>(
    data: &mut [u8],
    address: &mut A,
    ip_header_len: usize,
    nat_table_v4: &TransparentNatTableV4,
    proxy_port: u16,
    tls_port: u16,
) -> bool
where
    A: SetOutboundFlag,
{
    if data.len() < ip_header_len + 20 {
        return false;
    }

    let src_port = u16::from_be_bytes([data[ip_header_len], data[ip_header_len + 1]]);
    let dst_port = u16::from_be_bytes([data[ip_header_len + 2], data[ip_header_len + 3]]);
    if src_port != proxy_port && src_port != tls_port {
        return false;
    }

    let dst_ip = std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let is_closing = match etherparse::TcpHeaderSlice::from_slice(&data[ip_header_len..]) {
        Ok(tcp_slice) => tcp_slice.fin() || tcp_slice.rst(),
        Err(_) => return false,
    };
    let expires_at = nat_expiration(Instant::now(), is_closing);
    let Some((orig_dst_ip, orig_dst_port)) =
        touch_nat_mapping_v4(nat_table_v4, dst_ip, dst_port, Instant::now(), expires_at)
    else {
        return false;
    };

    data[12..16].copy_from_slice(&orig_dst_ip.octets());
    data[ip_header_len..ip_header_len + 2].copy_from_slice(&orig_dst_port.to_be_bytes());
    address.set_outbound_flag(false);
    true
}

#[cfg(target_os = "windows")]
fn handle_proxy_response_packet_v6<A>(
    data: &mut [u8],
    address: &mut A,
    ip_header_len: usize,
    nat_table_v6: &TransparentNatTableV6,
    proxy_port: u16,
    tls_port: u16,
) -> bool
where
    A: SetOutboundFlag,
{
    if data.len() < ip_header_len + 20 {
        return false;
    }

    let src_port = u16::from_be_bytes([data[ip_header_len], data[ip_header_len + 1]]);
    let dst_port = u16::from_be_bytes([data[ip_header_len + 2], data[ip_header_len + 3]]);
    if src_port != proxy_port && src_port != tls_port {
        return false;
    }

    let dst_ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap_or_default());
    let is_closing = match etherparse::TcpHeaderSlice::from_slice(&data[ip_header_len..]) {
        Ok(tcp_slice) => tcp_slice.fin() || tcp_slice.rst(),
        Err(_) => return false,
    };
    let expires_at = nat_expiration(Instant::now(), is_closing);
    let Some((orig_dst_ip, orig_dst_port)) =
        touch_nat_mapping_v6(nat_table_v6, dst_ip, dst_port, Instant::now(), expires_at)
    else {
        return false;
    };

    data[8..24].copy_from_slice(&orig_dst_ip.octets());
    data[ip_header_len..ip_header_len + 2].copy_from_slice(&orig_dst_port.to_be_bytes());
    address.set_outbound_flag(false);
    true
}

#[cfg(target_os = "windows")]
fn nat_expiration(now: Instant, is_closing: bool) -> Instant {
    now + if is_closing {
        NAT_ENTRY_CLOSING_TTL
    } else {
        NAT_ENTRY_ESTABLISHED_TTL
    }
}

#[cfg(target_os = "windows")]
unsafe fn extract_raw_handle<L: windivert::layer::WinDivertLayerTrait>(
    wd: &WinDivert<L>,
) -> HANDLE {
    // The wrapper does not expose the raw HANDLE, but it is the first field in
    // windivert::divert::WinDivert for this crate version.
    *(wd as *const _ as *const HANDLE)
}

#[cfg(target_os = "windows")]
trait SetOutboundFlag {
    fn set_outbound_flag(&mut self, outbound: bool);
}

#[cfg(target_os = "windows")]
impl SetOutboundFlag for windivert::address::WinDivertAddress<windivert::layer::NetworkLayer> {
    fn set_outbound_flag(&mut self, outbound: bool) {
        self.set_outbound(outbound);
    }
}

#[cfg(target_os = "windows")]
impl SetOutboundFlag for windivert::address::WinDivertAddress<windivert::layer::ForwardLayer> {
    fn set_outbound_flag(&mut self, outbound: bool) {
        self.set_outbound(outbound);
    }
}
