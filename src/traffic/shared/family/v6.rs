use std::net::{IpAddr, Ipv6Addr};

use etherparse::{IpHeaders, IpNumber, Ipv6HeaderSlice, PacketBuilder, PacketBuilderStep};
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

    fn read_tcp_ip_header_len(data: &[u8]) -> Option<usize> {
        match Ipv6HeaderSlice::from_slice(data) {
            Ok(ipv6_slice) if ipv6_slice.next_header() == IpNumber::TCP => {
                Some(ipv6_slice.slice().len())
            }
            _ => None,
        }
    }

    fn read_udp_ip_header_len(data: &[u8]) -> Option<usize> {
        match Ipv6HeaderSlice::from_slice(data) {
            Ok(ipv6_slice) if ipv6_slice.next_header() == IpNumber::UDP => {
                Some(ipv6_slice.slice().len())
            }
            _ => None,
        }
    }

    fn udp_packet_builder(
        source: Self::Addr,
        destination: Self::Addr,
        hop_limit: u8,
    ) -> PacketBuilderStep<IpHeaders> {
        PacketBuilder::ipv6(source.octets(), destination.octets(), hop_limit)
    }
}
