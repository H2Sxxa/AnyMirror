use std::borrow::Cow;
use std::time::Instant;

use etherparse::{IpNumber, Ipv4HeaderSlice, Ipv6HeaderSlice, TcpHeaderSlice};
use ipnet::{Ipv4Net, Ipv6Net};
use windivert::{
    address::WinDivertAddress,
    layer::{ForwardLayer, NetworkLayer},
};

use crate::traffic::shared::dns::FakeDnsServer;
use crate::traffic::shared::family::{v4::Ipv4PacketFamily, v6::Ipv6PacketFamily, IpPacketFamily};
use crate::traffic::shared::nat::{
    touch_nat_mapping, upsert_nat_mapping, TransparentNatTableV4, TransparentNatTableV6,
    NAT_ENTRY_CLOSING_TTL, NAT_ENTRY_ESTABLISHED_TTL,
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
    type NatTable;

    fn upsert_nat(
        nat_table: &Self::NatTable,
        client_ip: Self::Addr,
        client_port: u16,
        destination_ip: Self::Addr,
        destination_port: u16,
        expires_at: Instant,
    ) -> bool;

    fn touch_nat(
        nat_table: &Self::NatTable,
        client_ip: Self::Addr,
        client_port: u16,
        now: Instant,
        expires_at: Instant,
    ) -> Option<(Self::Addr, u16)>;
}

impl FamilyNatOps for Ipv4PacketFamily {
    type NatTable = TransparentNatTableV4;

    fn upsert_nat(
        nat_table: &Self::NatTable,
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
        nat_table: &Self::NatTable,
        client_ip: Self::Addr,
        client_port: u16,
        now: Instant,
        expires_at: Instant,
    ) -> Option<(Self::Addr, u16)> {
        touch_nat_mapping(nat_table, client_ip, client_port, now, expires_at)
    }
}

impl FamilyNatOps for Ipv6PacketFamily {
    type NatTable = TransparentNatTableV6;

    fn upsert_nat(
        nat_table: &Self::NatTable,
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
        nat_table: &Self::NatTable,
        client_ip: Self::Addr,
        client_port: u16,
        now: Instant,
        expires_at: Instant,
    ) -> Option<(Self::Addr, u16)> {
        touch_nat_mapping(nat_table, client_ip, client_port, now, expires_at)
    }
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
    build_fake_ip_dns_packet_for_family::<Ipv4PacketFamily>(packet_data, fake_dns_server).or_else(
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
    let request_src_ip = F::read_src_ip(packet_data)?;
    let request_dst_ip = F::read_dst_ip(packet_data)?;
    let (request_src_port, request_dst_port) = packet_ports(packet_data, ip_header_len)?;
    if request_dst_port != 53 {
        return None;
    }

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

fn ipv4_tcp_header_len(data: &[u8]) -> Option<usize> {
    match Ipv4HeaderSlice::from_slice(data) {
        Ok(ipv4_slice) if ipv4_slice.protocol() == IpNumber::TCP => Some(ipv4_slice.slice().len()),
        _ => None,
    }
}

fn ipv6_tcp_header_len(data: &[u8]) -> Option<usize> {
    match Ipv6HeaderSlice::from_slice(data) {
        Ok(ipv6_slice) if ipv6_slice.next_header() == IpNumber::TCP => {
            Some(ipv6_slice.slice().len())
        }
        _ => None,
    }
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
    if let Some(ip_header_len) = ipv4_tcp_header_len(data) {
        return handle_dns_tcp_packet_impl::<A, Ipv4PacketFamily>(
            data,
            address,
            ip_header_len,
            local_dns_port,
            nat_table_v4,
        );
    }

    if let Some(ip_header_len) = ipv6_tcp_header_len(data) {
        return handle_dns_tcp_packet_impl::<A, Ipv6PacketFamily>(
            data,
            address,
            ip_header_len,
            local_dns_port,
            nat_table_v6,
        );
    }

    PacketDisposition::Pass
}

fn handle_quic_packet(data: &[u8], fake_dns_server: Option<&FakeDnsServer>) -> PacketDisposition {
    let now = Instant::now();

    if let Some(disposition) =
        log_quic_drop_for_family::<Ipv4PacketFamily>(data, fake_dns_server, now)
    {
        return disposition;
    }

    if let Some(disposition) =
        log_quic_drop_for_family::<Ipv6PacketFamily>(data, fake_dns_server, now)
    {
        return disposition;
    }

    PacketDisposition::Drop
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
    if let Some(ip_header_len) = ipv4_tcp_header_len(data) {
        return handle_request_packet_impl::<A, Ipv4PacketFamily>(
            data,
            address,
            fake_dns_server,
            ip_header_len,
            fake_ipv4_range,
            nat_table_v4,
            proxy_port,
            tls_port,
        );
    }

    if let Some(ip_header_len) = ipv6_tcp_header_len(data) {
        return handle_request_packet_impl::<A, Ipv6PacketFamily>(
            data,
            address,
            fake_dns_server,
            ip_header_len,
            fake_ipv6_range,
            nat_table_v6,
            proxy_port,
            tls_port,
        );
    }

    PacketDisposition::Pass
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
    if let Some(ip_header_len) = ipv4_tcp_header_len(data) {
        return handle_proxy_response_packet_impl::<A, Ipv4PacketFamily>(
            data,
            address,
            ip_header_len,
            nat_table_v4,
            proxy_port,
            tls_port,
            local_dns_port,
        );
    }

    if let Some(ip_header_len) = ipv6_tcp_header_len(data) {
        return handle_proxy_response_packet_impl::<A, Ipv6PacketFamily>(
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

fn handle_request_packet_impl<A, F>(
    data: &mut [u8],
    address: &mut A,
    fake_dns_server: Option<&FakeDnsServer>,
    ip_header_len: usize,
    capture_range: F::Range,
    nat_table: &<F as FamilyNatOps>::NatTable,
    proxy_port: u16,
    tls_port: u16,
) -> PacketDisposition
where
    A: SetOutboundFlag,
    F: FamilyNatOps,
{
    if data.len() < ip_header_len + 20 {
        return PacketDisposition::Pass;
    }

    let Some(src_ip) = F::read_src_ip(data) else {
        return PacketDisposition::Pass;
    };
    let Some(dst_ip) = F::read_dst_ip(data) else {
        return PacketDisposition::Pass;
    };
    let Some((src_port, dst_port)) = packet_ports(data, ip_header_len) else {
        return PacketDisposition::Pass;
    };
    if dst_port == proxy_port || dst_port == tls_port || !F::contains(capture_range, &dst_ip) {
        return PacketDisposition::Pass;
    }
    let now = Instant::now();
    let Some(owned_domain) =
        fake_dns_server.and_then(|server| server.resolve_fake_domain(F::to_ip_addr(dst_ip), now))
    else {
        return PacketDisposition::Pass;
    };

    let Some((tcp_header_len, syn, is_closing)) = tcp_details(data, ip_header_len) else {
        return PacketDisposition::Pass;
    };
    let expires_at = nat_expiration(now, is_closing);
    if !F::upsert_nat(nat_table, src_ip, src_port, dst_ip, dst_port, expires_at) {
        tracing::error!(
            ip_family = F::LABEL,
            "WinDivert transparent NAT table lock poisoned"
        );
        return PacketDisposition::Pass;
    }

    let target_proxy_port = if dst_port == 443 {
        tls_port
    } else {
        proxy_port
    };
    F::set_request_destination_ip(data, src_ip);
    data[ip_header_len + 2..ip_header_len + 4].copy_from_slice(&target_proxy_port.to_be_bytes());

    let mut host_info = String::new();
    if ip_header_len + tcp_header_len < data.len() {
        let payload = &data[ip_header_len + tcp_header_len..];
        if let Some(host) = extract_host(payload) {
            host_info = host;
        }
    }

    address.set_outbound_flag(false);
    if !host_info.is_empty() {
        tracing::info!(
            ip_family = F::LABEL,
            client_port = src_port,
            fake_destination_ip = %dst_ip,
            domain = %owned_domain,
            destination_port = dst_port,
            target_proxy_port,
            host = host_info,
            "Intercepted fake-ip request and redirected it to the local proxy"
        );
    } else if syn {
        tracing::trace!(
            ip_family = F::LABEL,
            client_port = src_port,
            fake_destination_ip = %dst_ip,
            domain = %owned_domain,
            destination_port = dst_port,
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
    nat_table: &<F as FamilyNatOps>::NatTable,
) -> PacketDisposition
where
    A: SetOutboundFlag,
    F: FamilyNatOps,
{
    if data.len() < ip_header_len + 20 {
        return PacketDisposition::Pass;
    }

    let Some(src_ip) = F::read_src_ip(data) else {
        return PacketDisposition::Pass;
    };
    let Some(dst_ip) = F::read_dst_ip(data) else {
        return PacketDisposition::Pass;
    };
    let Some((src_port, dst_port)) = packet_ports(data, ip_header_len) else {
        return PacketDisposition::Pass;
    };
    if dst_port != 53 || src_port == local_dns_port {
        return PacketDisposition::Pass;
    }

    let Some((_, _, is_closing)) = tcp_details(data, ip_header_len) else {
        return PacketDisposition::Pass;
    };
    let expires_at = nat_expiration(Instant::now(), is_closing);
    if !F::upsert_nat(nat_table, src_ip, src_port, dst_ip, dst_port, expires_at) {
        tracing::error!(
            ip_family = F::LABEL,
            "WinDivert DNS NAT table lock poisoned"
        );
        return PacketDisposition::Pass;
    }

    F::set_request_destination_ip(data, src_ip);
    data[ip_header_len + 2..ip_header_len + 4].copy_from_slice(&local_dns_port.to_be_bytes());
    address.set_outbound_flag(false);
    tracing::debug!(
        ip_family = F::LABEL,
        client_port = src_port,
        original_dns_server = %dst_ip,
        local_dns_port,
        "Redirected DNS-over-TCP request to the local fake DNS server"
    );
    PacketDisposition::Modified
}

fn handle_proxy_response_packet_impl<A, F>(
    data: &mut [u8],
    address: &mut A,
    ip_header_len: usize,
    nat_table: &<F as FamilyNatOps>::NatTable,
    proxy_port: u16,
    tls_port: u16,
    local_dns_port: u16,
) -> PacketDisposition
where
    A: SetOutboundFlag,
    F: FamilyNatOps,
{
    if data.len() < ip_header_len + 20 {
        return PacketDisposition::Pass;
    }

    let Some((src_port, dst_port)) = packet_ports(data, ip_header_len) else {
        return PacketDisposition::Pass;
    };
    if src_port != proxy_port && src_port != tls_port && src_port != local_dns_port {
        return PacketDisposition::Pass;
    }

    let Some(dst_ip) = F::read_dst_ip(data) else {
        return PacketDisposition::Pass;
    };
    let Some((_, _, is_closing)) = tcp_details(data, ip_header_len) else {
        return PacketDisposition::Pass;
    };
    let expires_at = nat_expiration(Instant::now(), is_closing);
    let Some((orig_dst_ip, orig_dst_port)) =
        F::touch_nat(nat_table, dst_ip, dst_port, Instant::now(), expires_at)
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
