use std::hash::Hash;
use std::time::Instant;

use etherparse::TcpHeaderSlice;
use ipnet::{Ipv4Net, Ipv6Net};

use crate::traffic::shared::dns::FakeDnsServer;
use crate::traffic::shared::family::{IpPacketFamily, v4::Ipv4PacketFamily, v6::Ipv6PacketFamily};
use crate::traffic::shared::nat::{
    NAT_ENTRY_CLOSING_TTL, NAT_ENTRY_ESTABLISHED_TTL, TransparentNatTable, TransparentNatTableV4,
    TransparentNatTableV6, touch_nat_mapping, upsert_nat_mapping,
};
use crate::traffic::shared::sniff::extract_host;

use super::{PacketDisposition, PacketMetadata};

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

#[derive(Clone, Copy)]
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

pub(crate) fn packet_ports(data: &[u8], ip_header_len: usize) -> Option<(u16, u16)> {
    (data.len() >= ip_header_len + 4).then(|| {
        (
            u16::from_be_bytes([data[ip_header_len], data[ip_header_len + 1]]),
            u16::from_be_bytes([data[ip_header_len + 2], data[ip_header_len + 3]]),
        )
    })
}

pub(crate) fn handle_dns_tcp_packet<A>(
    data: &mut [u8],
    address: &mut A,
    local_dns_port: u16,
    nat_table_v4: &TransparentNatTableV4,
    nat_table_v6: &TransparentNatTableV6,
) -> PacketDisposition
where
    A: PacketMetadata,
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

pub(crate) fn handle_request_packet<A>(
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
    A: PacketMetadata,
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

pub(crate) fn handle_proxy_response_packet<A>(
    data: &mut [u8],
    address: &mut A,
    nat_table_v4: &TransparentNatTableV4,
    nat_table_v6: &TransparentNatTableV6,
    proxy_port: u16,
    tls_port: u16,
    local_dns_port: u16,
) -> PacketDisposition
where
    A: PacketMetadata,
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

fn with_tcp_packet_context<A, F, H>(
    data: &mut [u8],
    address: &mut A,
    ip_header_len: usize,
    handler: H,
) -> PacketDisposition
where
    F: IpPacketFamily,
    H: FnOnce(&mut [u8], &mut A, TcpPacketContext<F::Addr>) -> PacketDisposition,
{
    let Some(packet) = tcp_packet_context::<F>(data, ip_header_len) else {
        return PacketDisposition::Pass;
    };

    handler(data, address, packet)
}

fn detect_tcp_family(data: &[u8]) -> Option<DetectedTcpFamily> {
    if let Some(ip_header_len) = Ipv4PacketFamily::tcp_header_len(data) {
        return Some(DetectedTcpFamily::Ipv4(ip_header_len));
    }

    Ipv6PacketFamily::tcp_header_len(data).map(DetectedTcpFamily::Ipv6)
}

fn upsert_nat_packet<F>(
    nat_table: &TransparentNatTable<F::Addr>,
    packet: TcpPacketContext<F::Addr>,
    now: Instant,
    error_message: &'static str,
) -> bool
where
    F: FamilyNatOps,
    F::Addr: Copy + Eq + Hash,
{
    let expires_at = nat_expiration(now, packet.is_closing);
    if F::upsert_nat(
        nat_table,
        packet.src_ip,
        packet.src_port,
        packet.dst_ip,
        packet.dst_port,
        expires_at,
    ) {
        true
    } else {
        tracing::error!(ip_family = F::LABEL, "{error_message}");
        false
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
    A: PacketMetadata,
    F: FamilyNatOps,
    F::Addr: Copy + Eq + Hash,
{
    with_tcp_packet_context::<A, F, _>(data, address, ip_header_len, |data, address, packet| {
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

        if !upsert_nat_packet::<F>(
            nat_table,
            packet,
            now,
            "Transparent NAT table lock poisoned while redirecting fake-ip request",
        ) {
            return PacketDisposition::Pass;
        }

        let target_proxy_port = if packet.dst_port == 443 {
            tls_port
        } else {
            proxy_port
        };
        F::set_request_destination_ip(data, packet.src_ip);
        data[ip_header_len + 2..ip_header_len + 4]
            .copy_from_slice(&target_proxy_port.to_be_bytes());

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
    })
}

fn handle_dns_tcp_packet_impl<A, F>(
    data: &mut [u8],
    address: &mut A,
    ip_header_len: usize,
    local_dns_port: u16,
    nat_table: &TransparentNatTable<F::Addr>,
) -> PacketDisposition
where
    A: PacketMetadata,
    F: FamilyNatOps,
    F::Addr: Copy + Eq + Hash,
{
    with_tcp_packet_context::<A, F, _>(data, address, ip_header_len, |data, address, packet| {
        if packet.dst_port != 53 || packet.src_port == local_dns_port {
            return PacketDisposition::Pass;
        }

        if !upsert_nat_packet::<F>(
            nat_table,
            packet,
            Instant::now(),
            "Transparent NAT table lock poisoned while redirecting DNS-over-TCP request",
        ) {
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
    })
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
    A: PacketMetadata,
    F: FamilyNatOps,
    F::Addr: Copy + Eq + Hash,
{
    with_tcp_packet_context::<A, F, _>(data, address, ip_header_len, |data, address, packet| {
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
    })
}

fn nat_expiration(now: Instant, is_closing: bool) -> Instant {
    now + if is_closing {
        NAT_ENTRY_CLOSING_TTL
    } else {
        NAT_ENTRY_ESTABLISHED_TTL
    }
}
