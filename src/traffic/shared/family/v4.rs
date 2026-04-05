use std::net::{IpAddr, Ipv4Addr};

use etherparse::{IpHeaders, IpNumber, Ipv4HeaderSlice, PacketBuilder, PacketBuilderStep};
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

    fn read_tcp_ip_header_len(data: &[u8]) -> Option<usize> {
        match Ipv4HeaderSlice::from_slice(data) {
            Ok(ipv4_slice) if ipv4_slice.protocol() == IpNumber::TCP => {
                Some(ipv4_slice.slice().len())
            }
            _ => None,
        }
    }

    fn read_udp_ip_header_len(data: &[u8]) -> Option<usize> {
        match Ipv4HeaderSlice::from_slice(data) {
            Ok(ipv4_slice) if ipv4_slice.protocol() == IpNumber::UDP => {
                Some(ipv4_slice.slice().len())
            }
            _ => None,
        }
    }

    fn udp_packet_builder(
        source: Self::Addr,
        destination: Self::Addr,
        hop_limit: u8,
    ) -> PacketBuilderStep<IpHeaders> {
        PacketBuilder::ipv4(source.octets(), destination.octets(), hop_limit)
    }
}
