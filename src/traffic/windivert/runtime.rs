use std::time::Instant;
use std::{
    borrow::Cow,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use anyhow::{bail, Context, Result};
use etherparse::{IpNumber, Ipv4HeaderSlice, Ipv6HeaderSlice, PacketBuilder, TcpHeaderSlice};
use ipnet::{Ipv4Net, Ipv6Net};
use tokio::task;

use crate::config::AppConfig;
use crate::traffic::shared::dns::FakeDnsServer;
use crate::traffic::shared::nat::{
    new_transparent_nat_table_v4, new_transparent_nat_table_v6, spawn_nat_cleanup_task,
    touch_nat_mapping_v4, touch_nat_mapping_v6, upsert_nat_mapping_v4, upsert_nat_mapping_v6,
    TransparentNatTableV4, TransparentNatTableV6, NAT_ENTRY_CLOSING_TTL, NAT_ENTRY_ESTABLISHED_TTL,
};

use super::{
    config::{
        RuntimeBackend, TransparentCaptureKind, WinDivertConfig, WinDivertLayer, WinDivertRuntime,
    },
    filters,
    payload::extract_host,
};

#[cfg(target_os = "windows")]
use windivert::{
    address::WinDivertAddress,
    layer::{ForwardLayer, NetworkLayer, WinDivertLayerTrait},
    WinDivert,
};
#[cfg(target_os = "windows")]
use windivert_sys::ChecksumFlags;

pub fn run_transparent_windivert_runtimes(
    config: &AppConfig,
    fake_dns_server: FakeDnsServer,
    proxy_redirect_addr: SocketAddr,
    layer: WinDivertLayer,
) -> Result<()> {
    let proxy_port = proxy_redirect_addr.port();
    let tls_port = config.tls_port.unwrap_or(proxy_port + 1);
    let local_dns_port = fake_dns_server.listen_port();
    let fake_ipv4_range = config.shared.dns.fake_ipv4_range;
    let fake_ipv6_range = config.shared.dns.fake_ipv6_range;
    let nat_table_v4 = new_transparent_nat_table_v4();
    let nat_table_v6 = new_transparent_nat_table_v6();

    spawn_nat_cleanup_task(nat_table_v4.clone(), nat_table_v6.clone());

    tracing::info!(
        fake_ipv4_range = %fake_ipv4_range,
        fake_ipv6_range = %fake_ipv6_range,
        fake_dns_listen = %fake_dns_server.listen_addr(),
        "WinDivert transparent mode is using fake-ip routing"
    );

    let dns_runtime = WinDivertRuntime::new(WinDivertConfig {
        local_proxy_addr: proxy_redirect_addr,
        tls_port,
        filter: filters::build_transparent_dns_query_filter(),
        sniff: false,
        fake_ipv4_range,
        fake_ipv6_range,
        local_dns_port,
        layer,
        capture_kind: TransparentCaptureKind::DnsResponder,
        fake_dns_server: Some(fake_dns_server.clone()),
        transparent_nat_table_v4: nat_table_v4.clone(),
        transparent_nat_table_v6: nat_table_v6.clone(),
        ..Default::default()
    })?;
    dns_runtime.start()?;
    tracing::info!(
        plan = %dns_runtime.plan_summary(),
        "WinDivert fake-ip DNS responder started"
    );

    let dns_tcp_runtime = WinDivertRuntime::new(WinDivertConfig {
        local_proxy_addr: proxy_redirect_addr,
        tls_port,
        filter: filters::build_transparent_dns_tcp_request_filter(),
        sniff: false,
        fake_ipv4_range,
        fake_ipv6_range,
        local_dns_port,
        layer,
        capture_kind: TransparentCaptureKind::TcpDnsRedirect,
        fake_dns_server: Some(fake_dns_server.clone()),
        transparent_nat_table_v4: nat_table_v4.clone(),
        transparent_nat_table_v6: nat_table_v6.clone(),
        ..Default::default()
    })?;
    dns_tcp_runtime.start()?;
    tracing::info!(
        plan = %dns_tcp_runtime.plan_summary(),
        local_dns_port,
        "WinDivert DNS-over-TCP redirect started"
    );

    let request_runtime = WinDivertRuntime::new(WinDivertConfig {
        local_proxy_addr: proxy_redirect_addr,
        tls_port,
        filter: filters::build_transparent_fake_ip_tcp_request_filter(
            proxy_port,
            tls_port,
            fake_ipv4_range,
            fake_ipv6_range,
        ),
        sniff: false,
        fake_ipv4_range,
        fake_ipv6_range,
        local_dns_port,
        layer,
        capture_kind: TransparentCaptureKind::TcpRequestRedirect,
        fake_dns_server: Some(fake_dns_server.clone()),
        transparent_nat_table_v4: nat_table_v4.clone(),
        transparent_nat_table_v6: nat_table_v6.clone(),
        ..Default::default()
    })?;
    request_runtime.start()?;
    tracing::info!(
        plan = %request_runtime.plan_summary(),
        "WinDivert fake-ip request capture started"
    );

    let quic_runtime = WinDivertRuntime::new(WinDivertConfig {
        local_proxy_addr: proxy_redirect_addr,
        tls_port,
        filter: filters::build_transparent_fake_ip_quic_filter(fake_ipv4_range, fake_ipv6_range),
        sniff: false,
        fake_ipv4_range,
        fake_ipv6_range,
        local_dns_port,
        layer,
        capture_kind: TransparentCaptureKind::UdpQuicDrop,
        fake_dns_server: Some(fake_dns_server.clone()),
        transparent_nat_table_v4: nat_table_v4.clone(),
        transparent_nat_table_v6: nat_table_v6.clone(),
        ..Default::default()
    })?;
    quic_runtime.start()?;
    tracing::info!(
        plan = %quic_runtime.plan_summary(),
        "WinDivert fake-ip QUIC drop strategy started"
    );

    let response_runtime = WinDivertRuntime::new(WinDivertConfig {
        local_proxy_addr: proxy_redirect_addr,
        tls_port,
        filter: filters::build_transparent_tcp_proxy_response_filter(
            proxy_port,
            tls_port,
            local_dns_port,
        ),
        sniff: false,
        fake_ipv4_range,
        fake_ipv6_range,
        local_dns_port,
        layer,
        capture_kind: TransparentCaptureKind::TcpProxyResponse,
        fake_dns_server: Some(fake_dns_server),
        transparent_nat_table_v4: nat_table_v4,
        transparent_nat_table_v6: nat_table_v6,
        ..Default::default()
    })?;
    response_runtime.start()?;
    tracing::info!(
        plan = %response_runtime.plan_summary(),
        "WinDivert fake-ip proxy response capture started"
    );

    Ok(())
}

impl WinDivertRuntime {
    #[cfg(target_os = "windows")]
    pub fn start(&self) -> Result<()> {
        let RuntimeBackend::Windows(plan) = &self.backend else {
            bail!("WinDivert backend plan is missing on Windows");
        };

        let proxy_port = self.config.local_proxy_addr.port();
        let tls_port = self.config.tls_port;
        let local_dns_port = self.config.local_dns_port;
        let fake_ipv4_range = self.config.fake_ipv4_range;
        let fake_ipv6_range = self.config.fake_ipv6_range;
        let capture_kind = self.config.capture_kind.clone();
        let fake_dns_server = self.config.fake_dns_server.clone();
        let nat_table_v4 = self.config.transparent_nat_table_v4.clone();
        let nat_table_v6 = self.config.transparent_nat_table_v6.clone();

        match plan.layer {
            WinDivertLayer::Network => {
                let wd = WinDivert::network(&plan.filter, plan.priority, plan.flags)
                    .context("Failed to open WinDivert handle (Network Layer)")?;
                apply_windivert_params(&wd, plan);
                task::spawn_blocking(move || {
                    run_network_capture_loop(
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
                task::spawn_blocking(move || {
                    run_forward_capture_loop(
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

    #[cfg(not(target_os = "windows"))]
    pub fn start(&self) -> Result<()> {
        bail!("WinDivert backend is not supported on this platform.");
    }
}

#[cfg(target_os = "windows")]
fn apply_windivert_params<L: WinDivertLayerTrait>(
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
    wd: WinDivert<NetworkLayer>,
    capture_kind: TransparentCaptureKind,
    fake_dns_server: Option<FakeDnsServer>,
    fake_ipv4_range: Ipv4Net,
    fake_ipv6_range: Ipv6Net,
    nat_table_v4: TransparentNatTableV4,
    nat_table_v6: TransparentNatTableV6,
    proxy_port: u16,
    tls_port: u16,
    local_dns_port: u16,
) {
    let mut rx_buf = vec![0u8; 65535];
    loop {
        match wd.recv(Some(&mut rx_buf)) {
            Ok(mut packet) => {
                let disposition = if matches!(capture_kind, TransparentCaptureKind::DnsResponder) {
                    handle_dns_query_packet(
                        &mut packet.data,
                        &mut packet.address,
                        fake_dns_server.as_ref(),
                    )
                } else {
                    process_packet(
                        packet.data.to_mut(),
                        &mut packet.address,
                        &capture_kind,
                        fake_dns_server.as_ref(),
                        fake_ipv4_range,
                        fake_ipv6_range,
                        &nat_table_v4,
                        &nat_table_v6,
                        proxy_port,
                        tls_port,
                        local_dns_port,
                    )
                };
                if disposition.should_recalculate_checksums() {
                    let _ = packet.recalculate_checksums(ChecksumFlags::new());
                }
                if disposition.should_reinject() {
                    if let Err(error) = wd.send(&packet) {
                        tracing::error!(?error, "WinDivert send failed");
                    }
                }
            }
            Err(error) => {
                tracing::error!(?error, "WinDivert recv failed");
                break;
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn run_forward_capture_loop(
    wd: WinDivert<ForwardLayer>,
    capture_kind: TransparentCaptureKind,
    fake_dns_server: Option<FakeDnsServer>,
    fake_ipv4_range: Ipv4Net,
    fake_ipv6_range: Ipv6Net,
    nat_table_v4: TransparentNatTableV4,
    nat_table_v6: TransparentNatTableV6,
    proxy_port: u16,
    tls_port: u16,
    local_dns_port: u16,
) {
    let mut rx_buf = vec![0u8; 65535];
    loop {
        match wd.recv(Some(&mut rx_buf)) {
            Ok(mut packet) => {
                let disposition = if matches!(capture_kind, TransparentCaptureKind::DnsResponder) {
                    handle_dns_query_packet(
                        &mut packet.data,
                        &mut packet.address,
                        fake_dns_server.as_ref(),
                    )
                } else {
                    process_packet(
                        packet.data.to_mut(),
                        &mut packet.address,
                        &capture_kind,
                        fake_dns_server.as_ref(),
                        fake_ipv4_range,
                        fake_ipv6_range,
                        &nat_table_v4,
                        &nat_table_v6,
                        proxy_port,
                        tls_port,
                        local_dns_port,
                    )
                };
                if disposition.should_recalculate_checksums() {
                    let _ = packet.recalculate_checksums(ChecksumFlags::new());
                }
                if disposition.should_reinject() {
                    if let Err(error) = wd.send(&packet) {
                        tracing::error!(?error, "WinDivert send failed");
                    }
                }
            }
            Err(error) => {
                tracing::error!(?error, "WinDivert recv failed");
                break;
            }
        }
    }
}

#[cfg(target_os = "windows")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PacketDisposition {
    Pass,
    Modified,
    Drop,
}

#[cfg(target_os = "windows")]
impl PacketDisposition {
    fn should_recalculate_checksums(self) -> bool {
        matches!(self, Self::Modified)
    }

    fn should_reinject(self) -> bool {
        !matches!(self, Self::Drop)
    }
}

#[cfg(target_os = "windows")]
fn process_packet<A>(
    data: &mut [u8],
    address: &mut A,
    capture_kind: &TransparentCaptureKind,
    fake_dns_server: Option<&FakeDnsServer>,
    fake_ipv4_range: Ipv4Net,
    fake_ipv6_range: Ipv6Net,
    nat_table_v4: &TransparentNatTableV4,
    nat_table_v6: &TransparentNatTableV6,
    proxy_port: u16,
    tls_port: u16,
    local_dns_port: u16,
) -> PacketDisposition
where
    A: SetOutboundFlag,
{
    match capture_kind {
        TransparentCaptureKind::DnsResponder => PacketDisposition::Pass,
        TransparentCaptureKind::TcpRequestRedirect => handle_request_packet(
            data,
            address,
            fake_ipv4_range,
            fake_ipv6_range,
            nat_table_v4,
            nat_table_v6,
            proxy_port,
            tls_port,
        ),
        TransparentCaptureKind::TcpDnsRedirect => {
            handle_dns_tcp_packet(data, address, local_dns_port, nat_table_v4, nat_table_v6)
        }
        TransparentCaptureKind::TcpProxyResponse => handle_proxy_response_packet(
            data,
            address,
            nat_table_v4,
            nat_table_v6,
            proxy_port,
            tls_port,
            local_dns_port,
        ),
        TransparentCaptureKind::UdpQuicDrop => handle_quic_packet(data, fake_dns_server),
        TransparentCaptureKind::Generic => PacketDisposition::Pass,
    }
}

#[cfg(target_os = "windows")]
fn handle_dns_query_packet<A>(
    data: &mut Cow<'_, [u8]>,
    address: &mut A,
    fake_dns_server: Option<&FakeDnsServer>,
) -> PacketDisposition
where
    A: SetOutboundFlag,
{
    let Some(fake_dns_server) = fake_dns_server else {
        return PacketDisposition::Pass;
    };

    let response_packet = build_fake_ip_dns_packet(data.as_ref(), fake_dns_server);
    let Some(response_packet) = response_packet else {
        return PacketDisposition::Pass;
    };

    *data = Cow::Owned(response_packet);
    address.set_outbound_flag(false);
    PacketDisposition::Modified
}

#[cfg(target_os = "windows")]
fn build_fake_ip_dns_packet(
    packet_data: &[u8],
    fake_dns_server: &FakeDnsServer,
) -> Option<Vec<u8>> {
    if let Ok(ipv4_slice) = Ipv4HeaderSlice::from_slice(packet_data) {
        let ip_header_len = ipv4_slice.slice().len();
        if ipv4_slice.protocol() != IpNumber::UDP || packet_data.len() < ip_header_len + 8 {
            return None;
        }

        let src_ip = Ipv4Addr::new(
            packet_data[12],
            packet_data[13],
            packet_data[14],
            packet_data[15],
        );
        let dst_ip = Ipv4Addr::new(
            packet_data[16],
            packet_data[17],
            packet_data[18],
            packet_data[19],
        );
        let src_port =
            u16::from_be_bytes([packet_data[ip_header_len], packet_data[ip_header_len + 1]]);
        let dst_port = u16::from_be_bytes([
            packet_data[ip_header_len + 2],
            packet_data[ip_header_len + 3],
        ]);
        if dst_port != 53 {
            return None;
        }

        let dns_payload = &packet_data[ip_header_len + 8..];
        let response_payload = fake_dns_server.build_fake_response(dns_payload).ok()??;
        let builder =
            PacketBuilder::ipv4(dst_ip.octets(), src_ip.octets(), 64).udp(dst_port, src_port);
        let mut response_packet = Vec::with_capacity(builder.size(response_payload.len()));
        builder
            .write(&mut response_packet, &response_payload)
            .ok()?;
        return Some(response_packet);
    }

    if let Ok(ipv6_slice) = Ipv6HeaderSlice::from_slice(packet_data) {
        let ip_header_len = ipv6_slice.slice().len();
        if ipv6_slice.next_header() != IpNumber::UDP || packet_data.len() < ip_header_len + 8 {
            return None;
        }

        let src_ip = <[u8; 16]>::try_from(&packet_data[8..24])
            .ok()
            .map(Ipv6Addr::from)?;
        let dst_ip = <[u8; 16]>::try_from(&packet_data[24..40])
            .ok()
            .map(Ipv6Addr::from)?;
        let src_port =
            u16::from_be_bytes([packet_data[ip_header_len], packet_data[ip_header_len + 1]]);
        let dst_port = u16::from_be_bytes([
            packet_data[ip_header_len + 2],
            packet_data[ip_header_len + 3],
        ]);
        if dst_port != 53 {
            return None;
        }

        let dns_payload = &packet_data[ip_header_len + 8..];
        let response_payload = fake_dns_server.build_fake_response(dns_payload).ok()??;
        let builder =
            PacketBuilder::ipv6(dst_ip.octets(), src_ip.octets(), 64).udp(dst_port, src_port);
        let mut response_packet = Vec::with_capacity(builder.size(response_payload.len()));
        builder
            .write(&mut response_packet, &response_payload)
            .ok()?;
        return Some(response_packet);
    }

    None
}

#[cfg(target_os = "windows")]
fn handle_dns_tcp_packet<A>(
    data: &mut [u8],
    address: &mut A,
    local_dns_port: u16,
    nat_table_v4: &TransparentNatTableV4,
    nat_table_v6: &TransparentNatTableV6,
) -> PacketDisposition
where
    A: SetOutboundFlag,
{
    if let Some(ip_header_len) = match Ipv4HeaderSlice::from_slice(data) {
        Ok(ipv4_slice) if ipv4_slice.protocol() == IpNumber::TCP => Some(ipv4_slice.slice().len()),
        _ => None,
    } {
        return handle_dns_tcp_packet_v4(
            data,
            address,
            ip_header_len,
            local_dns_port,
            nat_table_v4,
        );
    }

    if let Some(ip_header_len) = match Ipv6HeaderSlice::from_slice(data) {
        Ok(ipv6_slice) if ipv6_slice.next_header() == IpNumber::TCP => {
            Some(ipv6_slice.slice().len())
        }
        _ => None,
    } {
        return handle_dns_tcp_packet_v6(
            data,
            address,
            ip_header_len,
            local_dns_port,
            nat_table_v6,
        );
    }

    PacketDisposition::Pass
}

#[cfg(target_os = "windows")]
fn handle_quic_packet(data: &[u8], fake_dns_server: Option<&FakeDnsServer>) -> PacketDisposition {
    let now = Instant::now();

    if Ipv4HeaderSlice::from_slice(data).is_ok() {
        let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let domain = fake_dns_server
            .and_then(|runtime| runtime.resolve_fake_domain(IpAddr::V4(dst_ip), now));
        tracing::info!(
            fake_destination_ip = %dst_ip,
            domain = domain.as_deref().unwrap_or("unknown"),
            "Dropping fake-ip QUIC packet to force TCP/TLS fallback"
        );
        return PacketDisposition::Drop;
    }

    if let Ok(_ipv6_slice) = Ipv6HeaderSlice::from_slice(data) {
        let dst_ip = match <[u8; 16]>::try_from(&data[24..40]) {
            Ok(bytes) => Ipv6Addr::from(bytes),
            Err(_) => return PacketDisposition::Drop,
        };
        let domain = fake_dns_server
            .and_then(|runtime| runtime.resolve_fake_domain(IpAddr::V6(dst_ip), now));
        tracing::info!(
            fake_destination_ip = %dst_ip,
            domain = domain.as_deref().unwrap_or("unknown"),
            "Dropping fake-ip QUIC packet to force TCP/TLS fallback"
        );
        return PacketDisposition::Drop;
    }

    PacketDisposition::Drop
}

#[cfg(target_os = "windows")]
fn handle_request_packet<A>(
    data: &mut [u8],
    address: &mut A,
    fake_ipv4_range: Ipv4Net,
    fake_ipv6_range: Ipv6Net,
    nat_table_v4: &TransparentNatTableV4,
    nat_table_v6: &TransparentNatTableV6,
    proxy_port: u16,
    tls_port: u16,
) -> PacketDisposition
where
    A: SetOutboundFlag,
{
    if let Some(ip_header_len) = match Ipv4HeaderSlice::from_slice(data) {
        Ok(ipv4_slice) if ipv4_slice.protocol() == IpNumber::TCP => Some(ipv4_slice.slice().len()),
        _ => None,
    } {
        return handle_request_packet_v4(
            data,
            address,
            ip_header_len,
            fake_ipv4_range,
            nat_table_v4,
            proxy_port,
            tls_port,
        );
    }

    if let Some(ip_header_len) = match Ipv6HeaderSlice::from_slice(data) {
        Ok(ipv6_slice) if ipv6_slice.next_header() == IpNumber::TCP => {
            Some(ipv6_slice.slice().len())
        }
        _ => None,
    } {
        return handle_request_packet_v6(
            data,
            address,
            ip_header_len,
            fake_ipv6_range,
            nat_table_v6,
            proxy_port,
            tls_port,
        );
    }

    PacketDisposition::Pass
}

#[cfg(target_os = "windows")]
fn handle_proxy_response_packet<A>(
    data: &mut [u8],
    address: &mut A,
    nat_table_v4: &TransparentNatTableV4,
    nat_table_v6: &TransparentNatTableV6,
    proxy_port: u16,
    tls_port: u16,
    local_dns_port: u16,
) -> PacketDisposition
where
    A: SetOutboundFlag,
{
    if let Some(ip_header_len) = match Ipv4HeaderSlice::from_slice(data) {
        Ok(ipv4_slice) if ipv4_slice.protocol() == IpNumber::TCP => Some(ipv4_slice.slice().len()),
        _ => None,
    } {
        return handle_proxy_response_packet_v4(
            data,
            address,
            ip_header_len,
            nat_table_v4,
            proxy_port,
            tls_port,
            local_dns_port,
        );
    }

    if let Some(ip_header_len) = match Ipv6HeaderSlice::from_slice(data) {
        Ok(ipv6_slice) if ipv6_slice.next_header() == IpNumber::TCP => {
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
            local_dns_port,
        );
    }

    PacketDisposition::Pass
}

#[cfg(target_os = "windows")]
fn handle_request_packet_v4<A>(
    data: &mut [u8],
    address: &mut A,
    ip_header_len: usize,
    fake_ipv4_range: Ipv4Net,
    nat_table_v4: &TransparentNatTableV4,
    proxy_port: u16,
    tls_port: u16,
) -> PacketDisposition
where
    A: SetOutboundFlag,
{
    if data.len() < ip_header_len + 20 {
        return PacketDisposition::Pass;
    }

    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let src_port = u16::from_be_bytes([data[ip_header_len], data[ip_header_len + 1]]);
    let dst_port = u16::from_be_bytes([data[ip_header_len + 2], data[ip_header_len + 3]]);
    if dst_port == proxy_port || dst_port == tls_port || !fake_ipv4_range.contains(&dst_ip) {
        return PacketDisposition::Pass;
    }

    let (tcp_header_len, syn, is_closing) = match TcpHeaderSlice::from_slice(&data[ip_header_len..])
    {
        Ok(tcp_slice) => (
            tcp_slice.slice().len(),
            tcp_slice.syn(),
            tcp_slice.fin() || tcp_slice.rst(),
        ),
        Err(_) => return PacketDisposition::Pass,
    };
    let expires_at = nat_expiration(Instant::now(), is_closing);
    if !upsert_nat_mapping_v4(nat_table_v4, src_ip, src_port, dst_ip, dst_port, expires_at) {
        tracing::error!("WinDivert IPv4 NAT table lock poisoned");
        return PacketDisposition::Pass;
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
            fake_destination_ip = %dst_ip,
            destination_port = dst_port,
            target_proxy_port,
            host = host_info,
            "Intercepted fake-ip IPv4 request and redirected it to the local proxy"
        );
    }

    PacketDisposition::Modified
}

#[cfg(target_os = "windows")]
fn handle_request_packet_v6<A>(
    data: &mut [u8],
    address: &mut A,
    ip_header_len: usize,
    fake_ipv6_range: Ipv6Net,
    nat_table_v6: &TransparentNatTableV6,
    proxy_port: u16,
    tls_port: u16,
) -> PacketDisposition
where
    A: SetOutboundFlag,
{
    if data.len() < ip_header_len + 20 || data.len() < 40 {
        return PacketDisposition::Pass;
    }

    let src_ip = match <[u8; 16]>::try_from(&data[8..24]) {
        Ok(bytes) => Ipv6Addr::from(bytes),
        Err(_) => return PacketDisposition::Pass,
    };
    let dst_ip = match <[u8; 16]>::try_from(&data[24..40]) {
        Ok(bytes) => Ipv6Addr::from(bytes),
        Err(_) => return PacketDisposition::Pass,
    };
    let src_port = u16::from_be_bytes([data[ip_header_len], data[ip_header_len + 1]]);
    let dst_port = u16::from_be_bytes([data[ip_header_len + 2], data[ip_header_len + 3]]);
    if dst_port == proxy_port || dst_port == tls_port || !fake_ipv6_range.contains(&dst_ip) {
        return PacketDisposition::Pass;
    }

    let (tcp_header_len, syn, is_closing) = match TcpHeaderSlice::from_slice(&data[ip_header_len..])
    {
        Ok(tcp_slice) => (
            tcp_slice.slice().len(),
            tcp_slice.syn(),
            tcp_slice.fin() || tcp_slice.rst(),
        ),
        Err(_) => return PacketDisposition::Pass,
    };
    let expires_at = nat_expiration(Instant::now(), is_closing);
    if !upsert_nat_mapping_v6(nat_table_v6, src_ip, src_port, dst_ip, dst_port, expires_at) {
        tracing::error!("WinDivert IPv6 NAT table lock poisoned");
        return PacketDisposition::Pass;
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
            fake_destination_ip = %dst_ip,
            destination_port = dst_port,
            target_proxy_port,
            host = host_info,
            "Intercepted fake-ip IPv6 request and redirected it to the local proxy"
        );
    }

    PacketDisposition::Modified
}

#[cfg(target_os = "windows")]
fn handle_dns_tcp_packet_v4<A>(
    data: &mut [u8],
    address: &mut A,
    ip_header_len: usize,
    local_dns_port: u16,
    nat_table_v4: &TransparentNatTableV4,
) -> PacketDisposition
where
    A: SetOutboundFlag,
{
    if data.len() < ip_header_len + 20 {
        return PacketDisposition::Pass;
    }

    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let src_port = u16::from_be_bytes([data[ip_header_len], data[ip_header_len + 1]]);
    let dst_port = u16::from_be_bytes([data[ip_header_len + 2], data[ip_header_len + 3]]);
    if dst_port != 53 || src_port == local_dns_port {
        return PacketDisposition::Pass;
    }

    let is_closing = match TcpHeaderSlice::from_slice(&data[ip_header_len..]) {
        Ok(tcp_slice) => tcp_slice.fin() || tcp_slice.rst(),
        Err(_) => return PacketDisposition::Pass,
    };
    let expires_at = nat_expiration(Instant::now(), is_closing);
    if !upsert_nat_mapping_v4(nat_table_v4, src_ip, src_port, dst_ip, dst_port, expires_at) {
        tracing::error!("WinDivert IPv4 DNS NAT table lock poisoned");
        return PacketDisposition::Pass;
    }

    data[16..20].copy_from_slice(&src_ip.octets());
    data[ip_header_len + 2..ip_header_len + 4].copy_from_slice(&local_dns_port.to_be_bytes());
    address.set_outbound_flag(false);
    tracing::debug!(
        client_port = src_port,
        original_dns_server = %dst_ip,
        local_dns_port,
        "Redirected DNS-over-TCP IPv4 request to the local fake DNS server"
    );
    PacketDisposition::Modified
}

#[cfg(target_os = "windows")]
fn handle_dns_tcp_packet_v6<A>(
    data: &mut [u8],
    address: &mut A,
    ip_header_len: usize,
    local_dns_port: u16,
    nat_table_v6: &TransparentNatTableV6,
) -> PacketDisposition
where
    A: SetOutboundFlag,
{
    if data.len() < ip_header_len + 20 || data.len() < 40 {
        return PacketDisposition::Pass;
    }

    let src_ip = match <[u8; 16]>::try_from(&data[8..24]) {
        Ok(bytes) => Ipv6Addr::from(bytes),
        Err(_) => return PacketDisposition::Pass,
    };
    let dst_ip = match <[u8; 16]>::try_from(&data[24..40]) {
        Ok(bytes) => Ipv6Addr::from(bytes),
        Err(_) => return PacketDisposition::Pass,
    };
    let src_port = u16::from_be_bytes([data[ip_header_len], data[ip_header_len + 1]]);
    let dst_port = u16::from_be_bytes([data[ip_header_len + 2], data[ip_header_len + 3]]);
    if dst_port != 53 || src_port == local_dns_port {
        return PacketDisposition::Pass;
    }

    let is_closing = match TcpHeaderSlice::from_slice(&data[ip_header_len..]) {
        Ok(tcp_slice) => tcp_slice.fin() || tcp_slice.rst(),
        Err(_) => return PacketDisposition::Pass,
    };
    let expires_at = nat_expiration(Instant::now(), is_closing);
    if !upsert_nat_mapping_v6(nat_table_v6, src_ip, src_port, dst_ip, dst_port, expires_at) {
        tracing::error!("WinDivert IPv6 DNS NAT table lock poisoned");
        return PacketDisposition::Pass;
    }

    data[24..40].copy_from_slice(&src_ip.octets());
    data[ip_header_len + 2..ip_header_len + 4].copy_from_slice(&local_dns_port.to_be_bytes());
    address.set_outbound_flag(false);
    tracing::debug!(
        client_port = src_port,
        original_dns_server = %dst_ip,
        local_dns_port,
        "Redirected DNS-over-TCP IPv6 request to the local fake DNS server"
    );
    PacketDisposition::Modified
}

#[cfg(target_os = "windows")]
fn handle_proxy_response_packet_v4<A>(
    data: &mut [u8],
    address: &mut A,
    ip_header_len: usize,
    nat_table_v4: &TransparentNatTableV4,
    proxy_port: u16,
    tls_port: u16,
    local_dns_port: u16,
) -> PacketDisposition
where
    A: SetOutboundFlag,
{
    if data.len() < ip_header_len + 20 {
        return PacketDisposition::Pass;
    }

    let src_port = u16::from_be_bytes([data[ip_header_len], data[ip_header_len + 1]]);
    let dst_port = u16::from_be_bytes([data[ip_header_len + 2], data[ip_header_len + 3]]);
    if src_port != proxy_port && src_port != tls_port && src_port != local_dns_port {
        return PacketDisposition::Pass;
    }

    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let is_closing = match TcpHeaderSlice::from_slice(&data[ip_header_len..]) {
        Ok(tcp_slice) => tcp_slice.fin() || tcp_slice.rst(),
        Err(_) => return PacketDisposition::Pass,
    };
    let expires_at = nat_expiration(Instant::now(), is_closing);
    let Some((orig_dst_ip, orig_dst_port)) =
        touch_nat_mapping_v4(nat_table_v4, dst_ip, dst_port, Instant::now(), expires_at)
    else {
        return PacketDisposition::Pass;
    };

    data[12..16].copy_from_slice(&orig_dst_ip.octets());
    data[ip_header_len..ip_header_len + 2].copy_from_slice(&orig_dst_port.to_be_bytes());
    address.set_outbound_flag(false);
    PacketDisposition::Modified
}

#[cfg(target_os = "windows")]
fn handle_proxy_response_packet_v6<A>(
    data: &mut [u8],
    address: &mut A,
    ip_header_len: usize,
    nat_table_v6: &TransparentNatTableV6,
    proxy_port: u16,
    tls_port: u16,
    local_dns_port: u16,
) -> PacketDisposition
where
    A: SetOutboundFlag,
{
    if data.len() < ip_header_len + 20 {
        return PacketDisposition::Pass;
    }

    let src_port = u16::from_be_bytes([data[ip_header_len], data[ip_header_len + 1]]);
    let dst_port = u16::from_be_bytes([data[ip_header_len + 2], data[ip_header_len + 3]]);
    if src_port != proxy_port && src_port != tls_port && src_port != local_dns_port {
        return PacketDisposition::Pass;
    }

    let dst_ip = match <[u8; 16]>::try_from(&data[24..40]) {
        Ok(bytes) => Ipv6Addr::from(bytes),
        Err(_) => return PacketDisposition::Pass,
    };
    let is_closing = match TcpHeaderSlice::from_slice(&data[ip_header_len..]) {
        Ok(tcp_slice) => tcp_slice.fin() || tcp_slice.rst(),
        Err(_) => return PacketDisposition::Pass,
    };
    let expires_at = nat_expiration(Instant::now(), is_closing);
    let Some((orig_dst_ip, orig_dst_port)) =
        touch_nat_mapping_v6(nat_table_v6, dst_ip, dst_port, Instant::now(), expires_at)
    else {
        return PacketDisposition::Pass;
    };

    data[8..24].copy_from_slice(&orig_dst_ip.octets());
    data[ip_header_len..ip_header_len + 2].copy_from_slice(&orig_dst_port.to_be_bytes());
    address.set_outbound_flag(false);
    PacketDisposition::Modified
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
trait SetOutboundFlag {
    fn set_outbound_flag(&mut self, outbound: bool);
}

#[cfg(target_os = "windows")]
impl SetOutboundFlag for WinDivertAddress<NetworkLayer> {
    fn set_outbound_flag(&mut self, outbound: bool) {
        self.set_outbound(outbound);
    }
}

#[cfg(target_os = "windows")]
impl SetOutboundFlag for WinDivertAddress<ForwardLayer> {
    fn set_outbound_flag(&mut self, outbound: bool) {
        self.set_outbound(outbound);
    }
}
