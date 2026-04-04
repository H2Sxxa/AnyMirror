use std::net::{IpAddr, Ipv4Addr};

use etherparse::{IpNumber, Ipv4HeaderSlice, PacketBuilder};
use ipnet::Ipv4Net;

use super::IpPacketFamily;

pub struct Ipv4PacketFamily;

impl IpPacketFamily for Ipv4PacketFamily {
    type Addr = Ipv4Addr;
    type Range = Ipv4Net;

    const LABEL: &'static str = "IPv4";

    fn read_src_ip(data: &[u8]) -> Option<Self::Addr> {
        (data.len() >= 16).then(|| Ipv4Addr::new(data[12], data[13], data[14], data[15]))
    }

    fn read_dst_ip(data: &[u8]) -> Option<Self::Addr> {
        (data.len() >= 20).then(|| Ipv4Addr::new(data[16], data[17], data[18], data[19]))
    }

    fn to_ip_addr(addr: Self::Addr) -> IpAddr {
        IpAddr::V4(addr)
    }

    fn set_request_destination_ip(data: &mut [u8], src_ip: Self::Addr) {
        data[16..20].copy_from_slice(&src_ip.octets());
    }

    fn set_response_source_ip(data: &mut [u8], orig_dst_ip: Self::Addr) {
        data[12..16].copy_from_slice(&orig_dst_ip.octets());
    }

    fn udp_header_len(data: &[u8]) -> Option<usize> {
        match Ipv4HeaderSlice::from_slice(data) {
            Ok(ipv4_slice) if ipv4_slice.protocol() == IpNumber::UDP => {
                let ip_header_len = ipv4_slice.slice().len();
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
        let builder = PacketBuilder::ipv4(request_dst_ip.octets(), request_src_ip.octets(), 64)
            .udp(request_dst_port, request_src_port);
        let mut response_packet = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut response_packet, payload).ok()?;
        Some(response_packet)
    }

    fn contains(range: Self::Range, addr: &Self::Addr) -> bool {
        range.contains(addr)
    }
}
