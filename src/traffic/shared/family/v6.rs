use std::net::{IpAddr, Ipv6Addr};

use etherparse::{IpNumber, Ipv6HeaderSlice, PacketBuilder};
use ipnet::Ipv6Net;

use super::IpPacketFamily;

pub struct Ipv6PacketFamily;

impl IpPacketFamily for Ipv6PacketFamily {
    type Addr = Ipv6Addr;
    type Range = Ipv6Net;

    const LABEL: &'static str = "IPv6";

    fn read_src_ip(data: &[u8]) -> Option<Self::Addr> {
        <[u8; 16]>::try_from(data.get(8..24)?)
            .ok()
            .map(Ipv6Addr::from)
    }

    fn read_dst_ip(data: &[u8]) -> Option<Self::Addr> {
        <[u8; 16]>::try_from(data.get(24..40)?)
            .ok()
            .map(Ipv6Addr::from)
    }

    fn to_ip_addr(addr: Self::Addr) -> IpAddr {
        IpAddr::V6(addr)
    }

    fn set_request_destination_ip(data: &mut [u8], src_ip: Self::Addr) {
        data[24..40].copy_from_slice(&src_ip.octets());
    }

    fn set_response_source_ip(data: &mut [u8], orig_dst_ip: Self::Addr) {
        data[8..24].copy_from_slice(&orig_dst_ip.octets());
    }

    fn udp_header_len(data: &[u8]) -> Option<usize> {
        match Ipv6HeaderSlice::from_slice(data) {
            Ok(ipv6_slice) if ipv6_slice.next_header() == IpNumber::UDP => {
                let ip_header_len = ipv6_slice.slice().len();
                (data.len() >= ip_header_len + 8).then_some(ip_header_len)
            }
            _ => None,
        }
    }

    fn build_udp_response_packet(
        request_src_ip: Self::Addr,
        request_dst_ip: Self::Addr,
        request_src_port: u16,
        request_dst_port: u16,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let builder = PacketBuilder::ipv6(request_dst_ip.octets(), request_src_ip.octets(), 64)
            .udp(request_dst_port, request_src_port);
        let mut response_packet = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut response_packet, payload).ok()?;
        Some(response_packet)
    }

    fn contains(range: Self::Range, addr: &Self::Addr) -> bool {
        range.contains(addr)
    }
}
