pub mod v4;
pub mod v6;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use etherparse::{IpHeaders, PacketBuilderStep};
use ipnet::{Ipv4Net, Ipv6Net};

pub trait IpPacketRange<Addr> {
    fn contains_addr(self, addr: &Addr) -> bool;
}

impl IpPacketRange<Ipv4Addr> for Ipv4Net {
    fn contains_addr(self, addr: &Ipv4Addr) -> bool {
        self.contains(addr)
    }
}

impl IpPacketRange<Ipv6Addr> for Ipv6Net {
    fn contains_addr(self, addr: &Ipv6Addr) -> bool {
        self.contains(addr)
    }
}

pub trait IpPacketFamily {
    type Addr: Copy + std::fmt::Display;
    type Range: Copy + IpPacketRange<Self::Addr>;

    const LABEL: &'static str;

    fn read_src_ip(data: &[u8]) -> Option<Self::Addr>;
    fn read_dst_ip(data: &[u8]) -> Option<Self::Addr>;
    fn to_ip_addr(addr: Self::Addr) -> IpAddr;
    fn set_request_destination_ip(data: &mut [u8], src_ip: Self::Addr);
    fn set_response_source_ip(data: &mut [u8], orig_dst_ip: Self::Addr);
    fn read_tcp_ip_header_len(data: &[u8]) -> Option<usize>;
    fn read_udp_ip_header_len(data: &[u8]) -> Option<usize>;
    fn udp_packet_builder(
        source: Self::Addr,
        destination: Self::Addr,
        hop_limit: u8,
    ) -> PacketBuilderStep<IpHeaders>;

    fn tcp_header_len(data: &[u8]) -> Option<usize> {
        Self::read_tcp_ip_header_len(data)
    }

    fn udp_header_len(data: &[u8]) -> Option<usize> {
        let ip_header_len = Self::read_udp_ip_header_len(data)?;
        (data.len() >= ip_header_len + 8).then_some(ip_header_len)
    }

    fn build_udp_response_packet(
        request_src_ip: Self::Addr,
        request_dst_ip: Self::Addr,
        request_src_port: u16,
        request_dst_port: u16,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let builder = Self::udp_packet_builder(request_dst_ip, request_src_ip, 64)
            .udp(request_dst_port, request_src_port);
        let mut response_packet = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut response_packet, payload).ok()?;
        Some(response_packet)
    }

    fn contains(range: Self::Range, addr: &Self::Addr) -> bool {
        range.contains_addr(addr)
    }
}
