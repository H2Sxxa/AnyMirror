use std::borrow::Cow;
use std::hash::Hash;
use std::time::Instant;

use etherparse::TcpHeaderSlice;
use ipnet::{Ipv4Net, Ipv6Net};
use windivert::{
    address::WinDivertAddress,
    layer::{ForwardLayer, NetworkLayer},
};
use windivert_sys::address::WINDIVERT_ADDRESS;

use crate::traffic::shared::dns::FakeDnsServer;
use crate::traffic::shared::family::{IpPacketFamily, v4::Ipv4PacketFamily, v6::Ipv6PacketFamily};
use crate::traffic::shared::nat::{
    NAT_ENTRY_CLOSING_TTL, NAT_ENTRY_ESTABLISHED_TTL, TransparentNatTable, TransparentNatTableV4,
    TransparentNatTableV6, touch_nat_mapping, upsert_nat_mapping,
};
use crate::traffic::windivert::config::TransparentCaptureKind;
use crate::traffic::windivert::payload::extract_host;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PacketDisposition {
    Pass,
    Modified,
    Drop,
}

impl PacketDisposition {
    pub(super) fn should_recalculate_checksums(self) -> bool {
        matches!(self, Self::Modified)
    }

    pub(super) fn should_reinject(self) -> bool {
        !matches!(self, Self::Drop)
    }
}

trait FamilyNatOps: IpPacketFamily {
    fn upsert_nat(
        nat_table: &TransparentNatTable<Self::Addr>,
        client_ip: Self::Addr,
        client_port: u16,
        destination_ip: Self::Addr,
        destination_port: u16,
        expires_at: Instant,
    ) -> bool;

    fn touch_nat(
        nat_table: &TransparentNatTable<Self::Addr>,
        client_ip: Self::Addr,
        client_port: u16,
        now: Instant,
        expires_at: Instant,
    ) -> Option<(Self::Addr, u16)>;
}

impl<F> FamilyNatOps for F
where
    F: IpPacketFamily,
    F::Addr: Copy + Eq + Hash,
{
    fn upsert_nat(
        nat_table: &TransparentNatTable<Self::Addr>,
        client_ip: Self::Addr,
        client_port: u16,
        destination_ip: Self::Addr,
        destination_port: u16,
        expires_at: Instant,
    ) -> bool {
        upsert_nat_mapping(
            nat_table,
            client_ip,
            client_port,
            destination_ip,
            destination_port,
            expires_at,
        )
    }

    fn touch_nat(
        nat_table: &TransparentNatTable<Self::Addr>,
        client_ip: Self::Addr,
        client_port: u16,
        now: Instant,
        expires_at: Instant,
    ) -> Option<(Self::Addr, u16)> {
        touch_nat_mapping(nat_table, client_ip, client_port, now, expires_at)
    }
}

struct TcpPacketContext<Addr> {
    src_ip: Addr,
    dst_ip: Addr,
    src_port: u16,
    dst_port: u16,
    tcp_header_len: usize,
    syn: bool,
    is_closing: bool,
}

enum DetectedTcpFamily {
    Ipv4(usize),
    Ipv6(usize),
}

pub(super) fn process_packet<A>(
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
        TransparentCaptureKind::TcpRequestRedirect => handle_request_packet(
            data,
            address,
            fake_dns_server,
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
        TransparentCaptureKind::DnsResponder => {
            unreachable!("DnsResponder is handled before process_packet")
        }
    }
}

pub(super) fn handle_dns_query_packet<A>(
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

fn build_fake_ip_dns_packet(
    packet_data: &[u8],
    fake_dns_server: &FakeDnsServer,
) -> Option<Vec<u8>> {
    try_packet_families(
        || build_fake_ip_dns_packet_for_family::<Ipv4PacketFamily>(packet_data, fake_dns_server),
        || build_fake_ip_dns_packet_for_family::<Ipv6PacketFamily>(packet_data, fake_dns_server),
    )
}

fn build_fake_ip_dns_packet_for_family<F>(
    packet_data: &[u8],
    fake_dns_server: &FakeDnsServer,
) -> Option<Vec<u8>>
where
    F: IpPacketFamily,
{
    let ip_header_len = F::udp_header_len(packet_data)?;
    let Some((request_src_port, request_dst_port)) = packet_ports(packet_data, ip_header_len)
    else {
        return None;
    };
    if request_dst_port != 53 {
        return None;
    }

    let request_src_ip = F::read_src_ip(packet_data)?;
    let request_dst_ip = F::read_dst_ip(packet_data)?;
    let dns_payload = &packet_data[ip_header_len + 8..];
    let response_payload = fake_dns_server.build_fake_response(dns_payload).ok()??;
    F::build_udp_response_packet(
        request_src_ip,
        request_dst_ip,
        request_src_port,
        request_dst_port,
        &response_payload,
    )
}

fn packet_ports(data: &[u8], ip_header_len: usize) -> Option<(u16, u16)> {
    (data.len() >= ip_header_len + 4).then(|| {
        (
            u16::from_be_bytes([data[ip_header_len], data[ip_header_len + 1]]),
            u16::from_be_bytes([data[ip_header_len + 2], data[ip_header_len + 3]]),
        )
    })
}

fn tcp_details(data: &[u8], ip_header_len: usize) -> Option<(usize, bool, bool)> {
    let tcp_slice = TcpHeaderSlice::from_slice(&data[ip_header_len..]).ok()?;
    Some((
        tcp_slice.slice().len(),
        tcp_slice.syn(),
        tcp_slice.fin() || tcp_slice.rst(),
    ))
}

fn tcp_packet_context<F>(data: &[u8], ip_header_len: usize) -> Option<TcpPacketContext<F::Addr>>
where
    F: IpPacketFamily,
{
    if data.len() < ip_header_len + 20 {
        return None;
    }

    let src_ip = F::read_src_ip(data)?;
    let dst_ip = F::read_dst_ip(data)?;
    let (src_port, dst_port) = packet_ports(data, ip_header_len)?;
    let (tcp_header_len, syn, is_closing) = tcp_details(data, ip_header_len)?;

    Some(TcpPacketContext {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        tcp_header_len,
        syn,
        is_closing,
    })
}

fn try_packet_families<T, FV4, FV6>(ipv4: FV4, ipv6: FV6) -> Option<T>
where
    FV4: FnOnce() -> Option<T>,
    FV6: FnOnce() -> Option<T>,
{
    ipv4().or_else(ipv6)
}

fn detect_tcp_family(data: &[u8]) -> Option<DetectedTcpFamily> {
    if let Some(ip_header_len) = Ipv4PacketFamily::tcp_header_len(data) {
        return Some(DetectedTcpFamily::Ipv4(ip_header_len));
    }

    Ipv6PacketFamily::tcp_header_len(data).map(DetectedTcpFamily::Ipv6)
}

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
    match detect_tcp_family(data) {
        Some(DetectedTcpFamily::Ipv4(ip_header_len)) => {
            handle_dns_tcp_packet_impl::<A, Ipv4PacketFamily>(
                data,
                address,
                ip_header_len,
                local_dns_port,
                nat_table_v4,
            )
        }
        Some(DetectedTcpFamily::Ipv6(ip_header_len)) => {
            handle_dns_tcp_packet_impl::<A, Ipv6PacketFamily>(
                data,
                address,
                ip_header_len,
                local_dns_port,
                nat_table_v6,
            )
        }
        None => PacketDisposition::Pass,
    }
}

fn handle_quic_packet(data: &[u8], fake_dns_server: Option<&FakeDnsServer>) -> PacketDisposition {
    let now = Instant::now();

    try_packet_families(
        || log_quic_drop_for_family::<Ipv4PacketFamily>(data, fake_dns_server, now),
        || log_quic_drop_for_family::<Ipv6PacketFamily>(data, fake_dns_server, now),
    )
    .unwrap_or(PacketDisposition::Drop)
}

fn log_quic_drop_for_family<F>(
    data: &[u8],
    fake_dns_server: Option<&FakeDnsServer>,
    now: Instant,
) -> Option<PacketDisposition>
where
    F: IpPacketFamily,
{
    let dst_ip = F::read_dst_ip(data)?;
    let domain =
        fake_dns_server.and_then(|runtime| runtime.resolve_fake_domain(F::to_ip_addr(dst_ip), now));
    let Some(domain) = domain else {
        return Some(PacketDisposition::Pass);
    };
    tracing::info!(
        ip_family = F::LABEL,
        fake_destination_ip = %dst_ip,
        domain = %domain,
        "Dropping fake-ip QUIC packet to force TCP/TLS fallback"
    );
    Some(PacketDisposition::Drop)
}

fn handle_request_packet<A>(
    data: &mut [u8],
    address: &mut A,
    fake_dns_server: Option<&FakeDnsServer>,
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
    match detect_tcp_family(data) {
        Some(DetectedTcpFamily::Ipv4(ip_header_len)) => {
            handle_request_packet_impl::<A, Ipv4PacketFamily>(
                data,
                address,
                fake_dns_server,
                ip_header_len,
                fake_ipv4_range,
                nat_table_v4,
                proxy_port,
                tls_port,
            )
        }
        Some(DetectedTcpFamily::Ipv6(ip_header_len)) => {
            handle_request_packet_impl::<A, Ipv6PacketFamily>(
                data,
                address,
                fake_dns_server,
                ip_header_len,
                fake_ipv6_range,
                nat_table_v6,
                proxy_port,
                tls_port,
            )
        }
        None => PacketDisposition::Pass,
    }
}

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
    match detect_tcp_family(data) {
        Some(DetectedTcpFamily::Ipv4(ip_header_len)) => {
            handle_proxy_response_packet_impl::<A, Ipv4PacketFamily>(
                data,
                address,
                ip_header_len,
                nat_table_v4,
                proxy_port,
                tls_port,
                local_dns_port,
            )
        }
        Some(DetectedTcpFamily::Ipv6(ip_header_len)) => {
            handle_proxy_response_packet_impl::<A, Ipv6PacketFamily>(
                data,
                address,
                ip_header_len,
                nat_table_v6,
                proxy_port,
                tls_port,
                local_dns_port,
            )
        }
        None => PacketDisposition::Pass,
    }
}

fn handle_request_packet_impl<A, F>(
    data: &mut [u8],
    address: &mut A,
    fake_dns_server: Option<&FakeDnsServer>,
    ip_header_len: usize,
    capture_range: F::Range,
    nat_table: &TransparentNatTable<F::Addr>,
    proxy_port: u16,
    tls_port: u16,
) -> PacketDisposition
where
    A: SetOutboundFlag,
    F: FamilyNatOps,
    F::Addr: Copy + Eq + Hash,
{
    let Some(packet) = tcp_packet_context::<F>(data, ip_header_len) else {
        return PacketDisposition::Pass;
    };
    if packet.dst_port == proxy_port
        || packet.dst_port == tls_port
        || !F::contains(capture_range, &packet.dst_ip)
    {
        return PacketDisposition::Pass;
    }
    let now = Instant::now();
    let Some(owned_domain) = fake_dns_server
        .and_then(|server| server.resolve_fake_domain(F::to_ip_addr(packet.dst_ip), now))
    else {
        return PacketDisposition::Pass;
    };

    let expires_at = nat_expiration(now, packet.is_closing);
    if !F::upsert_nat(
        nat_table,
        packet.src_ip,
        packet.src_port,
        packet.dst_ip,
        packet.dst_port,
        expires_at,
    ) {
        tracing::error!(
            ip_family = F::LABEL,
            "WinDivert transparent NAT table lock poisoned"
        );
        return PacketDisposition::Pass;
    }

    let target_proxy_port = if packet.dst_port == 443 {
        tls_port
    } else {
        proxy_port
    };
    F::set_request_destination_ip(data, packet.src_ip);
    data[ip_header_len + 2..ip_header_len + 4].copy_from_slice(&target_proxy_port.to_be_bytes());

    let mut host_info = String::new();
    if ip_header_len + packet.tcp_header_len < data.len() {
        let payload = &data[ip_header_len + packet.tcp_header_len..];
        if let Some(host) = extract_host(payload) {
            host_info = host;
        }
    }

    address.set_outbound_flag(false);
    if !host_info.is_empty() {
        tracing::info!(
            ip_family = F::LABEL,
            client_port = packet.src_port,
            fake_destination_ip = %packet.dst_ip,
            domain = %owned_domain,
            destination_port = packet.dst_port,
            target_proxy_port,
            host = host_info,
            "Intercepted fake-ip request and redirected it to the local proxy"
        );
    } else if packet.syn {
        tracing::trace!(
            ip_family = F::LABEL,
            client_port = packet.src_port,
            fake_destination_ip = %packet.dst_ip,
            domain = %owned_domain,
            destination_port = packet.dst_port,
            target_proxy_port,
            "Intercepted fake-ip TCP SYN and redirected it to the local proxy"
        );
    }

    PacketDisposition::Modified
}

fn handle_dns_tcp_packet_impl<A, F>(
    data: &mut [u8],
    address: &mut A,
    ip_header_len: usize,
    local_dns_port: u16,
    nat_table: &TransparentNatTable<F::Addr>,
) -> PacketDisposition
where
    A: SetOutboundFlag,
    F: FamilyNatOps,
    F::Addr: Copy + Eq + Hash,
{
    let Some(packet) = tcp_packet_context::<F>(data, ip_header_len) else {
        return PacketDisposition::Pass;
    };
    if packet.dst_port != 53 || packet.src_port == local_dns_port {
        return PacketDisposition::Pass;
    }

    let expires_at = nat_expiration(Instant::now(), packet.is_closing);
    if !F::upsert_nat(
        nat_table,
        packet.src_ip,
        packet.src_port,
        packet.dst_ip,
        packet.dst_port,
        expires_at,
    ) {
        tracing::error!(
            ip_family = F::LABEL,
            "WinDivert DNS NAT table lock poisoned"
        );
        return PacketDisposition::Pass;
    }

    F::set_request_destination_ip(data, packet.src_ip);
    data[ip_header_len + 2..ip_header_len + 4].copy_from_slice(&local_dns_port.to_be_bytes());
    address.set_outbound_flag(false);
    tracing::debug!(
        ip_family = F::LABEL,
        client_port = packet.src_port,
        original_dns_server = %packet.dst_ip,
        local_dns_port,
        "Redirected DNS-over-TCP request to the local fake DNS server"
    );
    PacketDisposition::Modified
}

fn handle_proxy_response_packet_impl<A, F>(
    data: &mut [u8],
    address: &mut A,
    ip_header_len: usize,
    nat_table: &TransparentNatTable<F::Addr>,
    proxy_port: u16,
    tls_port: u16,
    local_dns_port: u16,
) -> PacketDisposition
where
    A: SetOutboundFlag,
    F: FamilyNatOps,
    F::Addr: Copy + Eq + Hash,
{
    let Some(packet) = tcp_packet_context::<F>(data, ip_header_len) else {
        return PacketDisposition::Pass;
    };
    if packet.src_port != proxy_port
        && packet.src_port != tls_port
        && packet.src_port != local_dns_port
    {
        return PacketDisposition::Pass;
    }

    let now = Instant::now();
    let expires_at = nat_expiration(now, packet.is_closing);
    let Some((orig_dst_ip, orig_dst_port)) =
        F::touch_nat(nat_table, packet.dst_ip, packet.dst_port, now, expires_at)
    else {
        return PacketDisposition::Pass;
    };

    F::set_response_source_ip(data, orig_dst_ip);
    data[ip_header_len..ip_header_len + 2].copy_from_slice(&orig_dst_port.to_be_bytes());
    address.set_outbound_flag(false);
    PacketDisposition::Modified
}

fn nat_expiration(now: Instant, is_closing: bool) -> Instant {
    now + if is_closing {
        NAT_ENTRY_CLOSING_TTL
    } else {
        NAT_ENTRY_ESTABLISHED_TTL
    }
}

pub(super) trait SetOutboundFlag {
    fn set_outbound_flag(&mut self, outbound: bool);
}

impl SetOutboundFlag for WinDivertAddress<NetworkLayer> {
    fn set_outbound_flag(&mut self, outbound: bool) {
        self.set_outbound(outbound);
    }
}

impl SetOutboundFlag for WinDivertAddress<ForwardLayer> {
    fn set_outbound_flag(&mut self, outbound: bool) {
        self.set_outbound(outbound);
    }
}

impl SetOutboundFlag for WINDIVERT_ADDRESS {
    fn set_outbound_flag(&mut self, outbound: bool) {
        self.set_outbound(outbound);
    }
}
