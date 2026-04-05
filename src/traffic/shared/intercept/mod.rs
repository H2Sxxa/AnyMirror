mod tcp;

use std::borrow::Cow;
use std::time::Instant;

use ipnet::{Ipv4Net, Ipv6Net};

use crate::traffic::shared::dns::FakeDnsServer;
use crate::traffic::shared::family::{IpPacketFamily, v4::Ipv4PacketFamily, v6::Ipv6PacketFamily};
use crate::traffic::shared::nat::{TransparentNatTableV4, TransparentNatTableV6};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TransparentCaptureKind {
    TcpRequestRedirect,
    TcpDnsRedirect,
    TcpProxyResponse,
    DnsResponder,
    UdpQuicDrop,
    Generic,
}

impl Default for TransparentCaptureKind {
    fn default() -> Self {
        Self::Generic
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PacketDisposition {
    Pass,
    Modified,
    Drop,
}

impl PacketDisposition {
    pub(crate) fn should_recalculate_checksums(self) -> bool {
        matches!(self, Self::Modified)
    }

    pub(crate) fn should_reinject(self) -> bool {
        !matches!(self, Self::Drop)
    }
}

pub(crate) trait PacketMetadata {
    fn set_outbound_flag(&mut self, outbound: bool);
}

pub(crate) fn process_packet<A>(
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
    A: PacketMetadata,
{
    match capture_kind {
        TransparentCaptureKind::TcpRequestRedirect => tcp::handle_request_packet(
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
            tcp::handle_dns_tcp_packet(data, address, local_dns_port, nat_table_v4, nat_table_v6)
        }
        TransparentCaptureKind::TcpProxyResponse => tcp::handle_proxy_response_packet(
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

pub(crate) fn handle_dns_query_packet<A>(
    data: &mut Cow<'_, [u8]>,
    address: &mut A,
    fake_dns_server: Option<&FakeDnsServer>,
) -> PacketDisposition
where
    A: PacketMetadata,
{
    let Some(fake_dns_server) = fake_dns_server else {
        return PacketDisposition::Pass;
    };

    let Some(response_packet) = build_fake_ip_dns_packet(data.as_ref(), fake_dns_server) else {
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
    let (request_src_port, request_dst_port) = tcp::packet_ports(packet_data, ip_header_len)?;
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

fn try_packet_families<T, FV4, FV6>(ipv4: FV4, ipv6: FV6) -> Option<T>
where
    FV4: FnOnce() -> Option<T>,
    FV6: FnOnce() -> Option<T>,
{
    ipv4().or_else(ipv6)
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
